# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from scripts.extractors.kaitai.mach_o import MachO
class MachOFat(KaitaiStruct):
    """This is a simple container format that encapsulates multiple Mach-O files,
    each generally for a different architecture. XNU can execute these files just
    like single-arch Mach-Os and will pick the appropriate entry.
    
    .. seealso::
       Source - https://opensource.apple.com/source/xnu/xnu-7195.121.3/EXTERNAL_HEADERS/mach-o/fat.h.auto.html
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(4)
        if not self.magic == b"\xCA\xFE\xBA\xBE":
            raise kaitaistruct.ValidationNotEqualError(b"\xCA\xFE\xBA\xBE", self.magic, self._io, u"/seq/0")
        self.num_fat_arch = self._io.read_u4be()
        self.fat_archs = []
        for i in range(self.num_fat_arch):
            self.fat_archs.append(MachOFat.FatArch(self._io, self, self._root))


    class FatArch(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.cpu_type = KaitaiStream.resolve_enum(MachO.CpuType, self._io.read_u4be())
            self.cpu_subtype = self._io.read_u4be()
            self.ofs_object = self._io.read_u4be()
            self.len_object = self._io.read_u4be()
            self.align = self._io.read_u4be()

        @property
        def object(self):
            if hasattr(self, '_m_object'):
                return self._m_object

            _pos = self._io.pos()
            self._io.seek(self.ofs_object)
            self._raw__m_object = self._io.read_bytes(self.len_object)
            _io__raw__m_object = KaitaiStream(BytesIO(self._raw__m_object))
            self._m_object = MachO(_io__raw__m_object)
            self._io.seek(_pos)
            return getattr(self, '_m_object', None)



