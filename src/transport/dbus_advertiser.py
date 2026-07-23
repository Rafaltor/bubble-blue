"""
Extended LE advertising through bluetoothd's D-Bus ``LEAdvertisingManager1``.

Why D-Bus and not ``btmgmt``?
-----------------------------
The public Hello broadcast (anon_id + neighbor list + MPR set) is larger than the
31-byte legacy AD limit, so it must go out as **Extended Advertising**. On the
target controllers the raw MGMT path is unusable: ``Add Extended Advertising
Parameters`` succeeds but ``Add Extended Advertising Data`` is rejected with
``Invalid Parameters (0x0d)`` because ``bluetoothd`` co-owns the adapter and
reclaims any advertising instance added by a third-party MGMT client (``btmgmt
advinfo`` immediately drops back to 0 items). The plain 7-byte beacon works only
because legacy ``add-adv`` sets params+data in a single command.

The supported route is to register an ``org.bluez.LEAdvertisement1`` object with
``bluetoothd`` itself, which then programs *LE Set Extended Advertising
Parameters / Data / Enable* automatically for any payload over 31 bytes. This is
verified on-device (btmon shows the extended-advertising HCI commands with
``Secondary PHY: LE 1M``). A ``peripheral`` advertisement stays **connectable**,
so the same broadcast also accepts incoming L2CAP links.

The advertisement is dynamic: :meth:`update` swaps the manufacturer payload
(re-registering the object, since ``bluetoothd`` reads advertisement properties
once at registration time) so a node can refresh its Hello as its neighbor set
and sequence number evolve.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

try:  # dbus-fast is an optional runtime dependency (see requirements.txt).
    from dbus_fast import BusType, Variant
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import PropertyAccess, ServiceInterface, dbus_property, method

    _DBUS_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # noqa: BLE001 - surface a clear error only when used.
    _DBUS_IMPORT_ERROR = exc
    ServiceInterface = object  # type: ignore[assignment,misc]

    def method(*_a, **_k):  # type: ignore[misc]
        def _decorator(fn):
            return fn

        return _decorator

    def dbus_property(*_a, **_k):  # type: ignore[misc]
        def _decorator(fn):
            return fn

        return _decorator


_BLUEZ = "org.bluez"
_ADV_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
_ADV_IFACE = "org.bluez.LEAdvertisement1"


if _DBUS_IMPORT_ERROR is None:

    class _Advertisement(ServiceInterface):
        """A single ``org.bluez.LEAdvertisement1`` object with fixed properties."""

        def __init__(
            self,
            *,
            company_id: int,
            value: bytes,
            adv_type: str,
            discoverable: bool,
        ) -> None:
            super().__init__(_ADV_IFACE)
            self._type = adv_type
            self._discoverable = discoverable
            self._mfg = {int(company_id): Variant("ay", bytes(value))}

        @dbus_property(access=PropertyAccess.READ)
        def Type(self) -> "s":  # noqa: N802,F821
            return self._type

        @dbus_property(access=PropertyAccess.READ)
        def ManufacturerData(self) -> "a{qv}":  # noqa: N802,F821
            return self._mfg

        @dbus_property(access=PropertyAccess.READ)
        def Discoverable(self) -> "b":  # noqa: N802,F821
            return self._discoverable

        @dbus_property(access=PropertyAccess.READ)
        def IncludeTxPower(self) -> "b":  # noqa: N802,F821
            return False

        @method()
        def Release(self):  # noqa: N802
            return


class DBusLEAdvertiser:
    """
    Manage one extended-advertising set via bluetoothd D-Bus.

    ``start()`` registers a connectable advertisement carrying ``value`` as
    Manufacturer Specific Data for ``company_id``. ``update(value)`` re-registers
    with a fresh payload. ``stop()`` unregisters and drops the bus connection.

    All D-Bus work runs on a private asyncio loop in a background thread; the
    public methods are thread-safe and block briefly for the operation to apply.
    """

    def __init__(
        self,
        *,
        interface: str | int = 0,
        company_id: int,
        value: bytes,
        adv_type: str = "peripheral",
        discoverable: bool = True,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self._adapter_path = _adapter_path(interface)
        self._company_id = int(company_id)
        self._value = bytes(value)
        self._adv_type = adv_type
        self._discoverable = discoverable
        self._log = log or (lambda _msg: None)

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._bus = None
        self._mgr = None
        self._path: str | None = None
        self._counter = 0
        self._started = False

    @staticmethod
    def available() -> bool:
        """True if the dbus-fast dependency imported successfully."""
        return _DBUS_IMPORT_ERROR is None

    @property
    def running(self) -> bool:
        return self._started

    def start(self) -> None:
        if self._started:
            return
        if _DBUS_IMPORT_ERROR is not None:
            raise RuntimeError(
                "dbus-fast is required for extended advertising; install it "
                f"(pip install dbus-fast). Import error: {_DBUS_IMPORT_ERROR!r}"
            )
        self._thread = threading.Thread(
            target=self._run_loop, name="bb-dbus-adv", daemon=True
        )
        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("D-Bus advertising loop failed to start in time")
        fut = asyncio.run_coroutine_threadsafe(self._register(self._value), self._loop)
        fut.result(timeout=10.0)
        self._started = True
        self._log(f"extended advertising registered on {self._adapter_path}")

    def update(self, value: bytes) -> None:
        """Replace the advertised manufacturer payload (re-register)."""
        value = bytes(value)
        if not self._started or self._loop is None:
            self._value = value
            return
        if value == self._value:
            return
        self._value = value
        fut = asyncio.run_coroutine_threadsafe(self._register(value), self._loop)
        try:
            fut.result(timeout=10.0)
        except Exception as exc:  # noqa: BLE001
            self._log(f"advertising update failed: {exc!r}")

    def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        if self._loop is not None:
            fut = asyncio.run_coroutine_threadsafe(self._teardown(), self._loop)
            try:
                fut.result(timeout=5.0)
            except Exception:  # noqa: BLE001
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._log(f"extended advertising stopped on {self._adapter_path}")

    # Alias used elsewhere in the codebase for advertiser teardown.
    def mute(self) -> None:
        self.stop()

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    async def _ensure_bus(self) -> None:
        if self._bus is not None:
            return
        self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        introspect = await self._bus.introspect(_BLUEZ, self._adapter_path)
        obj = self._bus.get_proxy_object(_BLUEZ, self._adapter_path, introspect)
        self._mgr = obj.get_interface(_ADV_MANAGER_IFACE)

    async def _register(self, value: bytes) -> None:
        await self._ensure_bus()
        await self._unregister_current()
        self._counter += 1
        path = f"/org/bluez/bb/adv{self._counter}"
        adv = _Advertisement(
            company_id=self._company_id,
            value=value,
            adv_type=self._adv_type,
            discoverable=self._discoverable,
        )
        self._bus.export(path, adv)
        await self._mgr.call_register_advertisement(path, {})
        self._path = path

    async def _unregister_current(self) -> None:
        if self._path is None:
            return
        path = self._path
        self._path = None
        try:
            await self._mgr.call_unregister_advertisement(path)
        except Exception as exc:  # noqa: BLE001
            self._log(f"unregister {path} failed: {exc!r}")
        try:
            self._bus.unexport(path)
        except Exception:  # noqa: BLE001
            pass

    async def _teardown(self) -> None:
        await self._unregister_current()
        if self._bus is not None:
            try:
                self._bus.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self._bus = None
            self._mgr = None


def _adapter_path(interface: str | int) -> str:
    if isinstance(interface, int):
        return f"/org/bluez/hci{interface}"
    iface = interface.strip().lower()
    if iface.startswith("/org/bluez/"):
        return iface
    if iface.startswith("hci"):
        return f"/org/bluez/{iface}"
    return f"/org/bluez/hci{int(iface)}"
