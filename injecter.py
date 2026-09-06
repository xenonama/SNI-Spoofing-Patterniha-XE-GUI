# injecter.py (بدون تغییر)
import sys
from abc import ABC, abstractmethod

try:
    from pydivert import WinDivert, Packet
except Exception:  # allow --self-test / tests on machines without WinDivert
    WinDivert = None  # type: ignore

    class Packet:  # type: ignore
        pass


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        import threading
        if WinDivert is None:
            raise RuntimeError(
                "pydivert/WinDivert not available. Install with "
                "'pip install -r requirements.txt' on Windows.")
        self.w: WinDivert = WinDivert(w_filter)
        self._stop = threading.Event()

    @abstractmethod
    def inject(self, packet: Packet):
        raise NotImplementedError

    def stop(self):
        self._stop.set()
        try:
            self.w.close()
        except Exception:
            pass

    def run(self):
        with self.w:
            while not self._stop.is_set():
                try:
                    packet = self.w.recv(65575)
                except Exception:
                    if self._stop.is_set():
                        break
                    continue
                self.inject(packet)
