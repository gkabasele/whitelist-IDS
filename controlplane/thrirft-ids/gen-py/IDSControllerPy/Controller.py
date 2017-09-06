#
# Autogenerated by Thrift Compiler (0.9.2)
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#
#  options string: py
#

from thrift.Thrift import TType, TMessageType, TException, TApplicationException
from ttypes import *
from thrift.Thrift import TProcessor
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol, TProtocol
try:
  from thrift.protocol import fastbinary
except:
  fastbinary = None


class Iface:
  def mirror(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    pass

  def redirect(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    pass

  def block(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    pass

  def allow(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    pass


class Client(Iface):
  def __init__(self, iprot, oprot=None):
    self._iprot = self._oprot = iprot
    if oprot is not None:
      self._oprot = oprot
    self._seqid = 0

  def mirror(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    self.send_mirror(req, switches)
    self.recv_mirror()

  def send_mirror(self, req, switches):
    self._oprot.writeMessageBegin('mirror', TMessageType.CALL, self._seqid)
    args = mirror_args()
    args.req = req
    args.switches = switches
    args.write(self._oprot)
    self._oprot.writeMessageEnd()
    self._oprot.trans.flush()

  def recv_mirror(self):
    iprot = self._iprot
    (fname, mtype, rseqid) = iprot.readMessageBegin()
    if mtype == TMessageType.EXCEPTION:
      x = TApplicationException()
      x.read(iprot)
      iprot.readMessageEnd()
      raise x
    result = mirror_result()
    result.read(iprot)
    iprot.readMessageEnd()
    if result.error is not None:
      raise result.error
    return

  def redirect(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    self.send_redirect(req, switches)
    self.recv_redirect()

  def send_redirect(self, req, switches):
    self._oprot.writeMessageBegin('redirect', TMessageType.CALL, self._seqid)
    args = redirect_args()
    args.req = req
    args.switches = switches
    args.write(self._oprot)
    self._oprot.writeMessageEnd()
    self._oprot.trans.flush()

  def recv_redirect(self):
    iprot = self._iprot
    (fname, mtype, rseqid) = iprot.readMessageBegin()
    if mtype == TMessageType.EXCEPTION:
      x = TApplicationException()
      x.read(iprot)
      iprot.readMessageEnd()
      raise x
    result = redirect_result()
    result.read(iprot)
    iprot.readMessageEnd()
    if result.error is not None:
      raise result.error
    return

  def block(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    self.send_block(req, switches)
    self.recv_block()

  def send_block(self, req, switches):
    self._oprot.writeMessageBegin('block', TMessageType.CALL, self._seqid)
    args = block_args()
    args.req = req
    args.switches = switches
    args.write(self._oprot)
    self._oprot.writeMessageEnd()
    self._oprot.trans.flush()

  def recv_block(self):
    iprot = self._iprot
    (fname, mtype, rseqid) = iprot.readMessageBegin()
    if mtype == TMessageType.EXCEPTION:
      x = TApplicationException()
      x.read(iprot)
      iprot.readMessageEnd()
      raise x
    result = block_result()
    result.read(iprot)
    iprot.readMessageEnd()
    if result.error is not None:
      raise result.error
    return

  def allow(self, req, switches):
    """
    Parameters:
     - req
     - switches
    """
    self.send_allow(req, switches)
    self.recv_allow()

  def send_allow(self, req, switches):
    self._oprot.writeMessageBegin('allow', TMessageType.CALL, self._seqid)
    args = allow_args()
    args.req = req
    args.switches = switches
    args.write(self._oprot)
    self._oprot.writeMessageEnd()
    self._oprot.trans.flush()

  def recv_allow(self):
    iprot = self._iprot
    (fname, mtype, rseqid) = iprot.readMessageBegin()
    if mtype == TMessageType.EXCEPTION:
      x = TApplicationException()
      x.read(iprot)
      iprot.readMessageEnd()
      raise x
    result = allow_result()
    result.read(iprot)
    iprot.readMessageEnd()
    if result.error is not None:
      raise result.error
    return


class Processor(Iface, TProcessor):
  def __init__(self, handler):
    self._handler = handler
    self._processMap = {}
    self._processMap["mirror"] = Processor.process_mirror
    self._processMap["redirect"] = Processor.process_redirect
    self._processMap["block"] = Processor.process_block
    self._processMap["allow"] = Processor.process_allow

  def process(self, iprot, oprot):
    (name, type, seqid) = iprot.readMessageBegin()
    if name not in self._processMap:
      iprot.skip(TType.STRUCT)
      iprot.readMessageEnd()
      x = TApplicationException(TApplicationException.UNKNOWN_METHOD, 'Unknown function %s' % (name))
      oprot.writeMessageBegin(name, TMessageType.EXCEPTION, seqid)
      x.write(oprot)
      oprot.writeMessageEnd()
      oprot.trans.flush()
      return
    else:
      self._processMap[name](self, seqid, iprot, oprot)
    return True

  def process_mirror(self, seqid, iprot, oprot):
    args = mirror_args()
    args.read(iprot)
    iprot.readMessageEnd()
    result = mirror_result()
    try:
      self._handler.mirror(args.req, args.switches)
    except IDSControllerException, error:
      result.error = error
    oprot.writeMessageBegin("mirror", TMessageType.REPLY, seqid)
    result.write(oprot)
    oprot.writeMessageEnd()
    oprot.trans.flush()

  def process_redirect(self, seqid, iprot, oprot):
    args = redirect_args()
    args.read(iprot)
    iprot.readMessageEnd()
    result = redirect_result()
    try:
      self._handler.redirect(args.req, args.switches)
    except IDSControllerException, error:
      result.error = error
    oprot.writeMessageBegin("redirect", TMessageType.REPLY, seqid)
    result.write(oprot)
    oprot.writeMessageEnd()
    oprot.trans.flush()

  def process_block(self, seqid, iprot, oprot):
    args = block_args()
    args.read(iprot)
    iprot.readMessageEnd()
    result = block_result()
    try:
      self._handler.block(args.req, args.switches)
    except IDSControllerException, error:
      result.error = error
    oprot.writeMessageBegin("block", TMessageType.REPLY, seqid)
    result.write(oprot)
    oprot.writeMessageEnd()
    oprot.trans.flush()

  def process_allow(self, seqid, iprot, oprot):
    args = allow_args()
    args.read(iprot)
    iprot.readMessageEnd()
    result = allow_result()
    try:
      self._handler.allow(args.req, args.switches)
    except IDSControllerException, error:
      result.error = error
    oprot.writeMessageBegin("allow", TMessageType.REPLY, seqid)
    result.write(oprot)
    oprot.writeMessageEnd()
    oprot.trans.flush()


# HELPER FUNCTIONS AND STRUCTURES

class mirror_args:
  """
  Attributes:
   - req
   - switches
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'req', (Flow, Flow.thrift_spec), None, ), # 1
    (2, TType.LIST, 'switches', (TType.I16,None), None, ), # 2
  )

  def __init__(self, req=None, switches=None,):
    self.req = req
    self.switches = switches

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.req = Flow()
          self.req.read(iprot)
        else:
          iprot.skip(ftype)
      elif fid == 2:
        if ftype == TType.LIST:
          self.switches = []
          (_etype3, _size0) = iprot.readListBegin()
          for _i4 in xrange(_size0):
            _elem5 = iprot.readI16();
            self.switches.append(_elem5)
          iprot.readListEnd()
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('mirror_args')
    if self.req is not None:
      oprot.writeFieldBegin('req', TType.STRUCT, 1)
      self.req.write(oprot)
      oprot.writeFieldEnd()
    if self.switches is not None:
      oprot.writeFieldBegin('switches', TType.LIST, 2)
      oprot.writeListBegin(TType.I16, len(self.switches))
      for iter6 in self.switches:
        oprot.writeI16(iter6)
      oprot.writeListEnd()
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.req)
    value = (value * 31) ^ hash(self.switches)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class mirror_result:
  """
  Attributes:
   - error
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'error', (IDSControllerException, IDSControllerException.thrift_spec), None, ), # 1
  )

  def __init__(self, error=None,):
    self.error = error

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.error = IDSControllerException()
          self.error.read(iprot)
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('mirror_result')
    if self.error is not None:
      oprot.writeFieldBegin('error', TType.STRUCT, 1)
      self.error.write(oprot)
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.error)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class redirect_args:
  """
  Attributes:
   - req
   - switches
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'req', (Flow, Flow.thrift_spec), None, ), # 1
    (2, TType.LIST, 'switches', (TType.I16,None), None, ), # 2
  )

  def __init__(self, req=None, switches=None,):
    self.req = req
    self.switches = switches

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.req = Flow()
          self.req.read(iprot)
        else:
          iprot.skip(ftype)
      elif fid == 2:
        if ftype == TType.LIST:
          self.switches = []
          (_etype10, _size7) = iprot.readListBegin()
          for _i11 in xrange(_size7):
            _elem12 = iprot.readI16();
            self.switches.append(_elem12)
          iprot.readListEnd()
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('redirect_args')
    if self.req is not None:
      oprot.writeFieldBegin('req', TType.STRUCT, 1)
      self.req.write(oprot)
      oprot.writeFieldEnd()
    if self.switches is not None:
      oprot.writeFieldBegin('switches', TType.LIST, 2)
      oprot.writeListBegin(TType.I16, len(self.switches))
      for iter13 in self.switches:
        oprot.writeI16(iter13)
      oprot.writeListEnd()
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.req)
    value = (value * 31) ^ hash(self.switches)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class redirect_result:
  """
  Attributes:
   - error
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'error', (IDSControllerException, IDSControllerException.thrift_spec), None, ), # 1
  )

  def __init__(self, error=None,):
    self.error = error

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.error = IDSControllerException()
          self.error.read(iprot)
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('redirect_result')
    if self.error is not None:
      oprot.writeFieldBegin('error', TType.STRUCT, 1)
      self.error.write(oprot)
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.error)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class block_args:
  """
  Attributes:
   - req
   - switches
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'req', (Flow, Flow.thrift_spec), None, ), # 1
    (2, TType.LIST, 'switches', (TType.I16,None), None, ), # 2
  )

  def __init__(self, req=None, switches=None,):
    self.req = req
    self.switches = switches

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.req = Flow()
          self.req.read(iprot)
        else:
          iprot.skip(ftype)
      elif fid == 2:
        if ftype == TType.LIST:
          self.switches = []
          (_etype17, _size14) = iprot.readListBegin()
          for _i18 in xrange(_size14):
            _elem19 = iprot.readI16();
            self.switches.append(_elem19)
          iprot.readListEnd()
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('block_args')
    if self.req is not None:
      oprot.writeFieldBegin('req', TType.STRUCT, 1)
      self.req.write(oprot)
      oprot.writeFieldEnd()
    if self.switches is not None:
      oprot.writeFieldBegin('switches', TType.LIST, 2)
      oprot.writeListBegin(TType.I16, len(self.switches))
      for iter20 in self.switches:
        oprot.writeI16(iter20)
      oprot.writeListEnd()
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.req)
    value = (value * 31) ^ hash(self.switches)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class block_result:
  """
  Attributes:
   - error
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'error', (IDSControllerException, IDSControllerException.thrift_spec), None, ), # 1
  )

  def __init__(self, error=None,):
    self.error = error

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.error = IDSControllerException()
          self.error.read(iprot)
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('block_result')
    if self.error is not None:
      oprot.writeFieldBegin('error', TType.STRUCT, 1)
      self.error.write(oprot)
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.error)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class allow_args:
  """
  Attributes:
   - req
   - switches
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'req', (Flow, Flow.thrift_spec), None, ), # 1
    (2, TType.LIST, 'switches', (TType.I16,None), None, ), # 2
  )

  def __init__(self, req=None, switches=None,):
    self.req = req
    self.switches = switches

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.req = Flow()
          self.req.read(iprot)
        else:
          iprot.skip(ftype)
      elif fid == 2:
        if ftype == TType.LIST:
          self.switches = []
          (_etype24, _size21) = iprot.readListBegin()
          for _i25 in xrange(_size21):
            _elem26 = iprot.readI16();
            self.switches.append(_elem26)
          iprot.readListEnd()
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('allow_args')
    if self.req is not None:
      oprot.writeFieldBegin('req', TType.STRUCT, 1)
      self.req.write(oprot)
      oprot.writeFieldEnd()
    if self.switches is not None:
      oprot.writeFieldBegin('switches', TType.LIST, 2)
      oprot.writeListBegin(TType.I16, len(self.switches))
      for iter27 in self.switches:
        oprot.writeI16(iter27)
      oprot.writeListEnd()
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.req)
    value = (value * 31) ^ hash(self.switches)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)

class allow_result:
  """
  Attributes:
   - error
  """

  thrift_spec = (
    None, # 0
    (1, TType.STRUCT, 'error', (IDSControllerException, IDSControllerException.thrift_spec), None, ), # 1
  )

  def __init__(self, error=None,):
    self.error = error

  def read(self, iprot):
    if iprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None and fastbinary is not None:
      fastbinary.decode_binary(self, iprot.trans, (self.__class__, self.thrift_spec))
      return
    iprot.readStructBegin()
    while True:
      (fname, ftype, fid) = iprot.readFieldBegin()
      if ftype == TType.STOP:
        break
      if fid == 1:
        if ftype == TType.STRUCT:
          self.error = IDSControllerException()
          self.error.read(iprot)
        else:
          iprot.skip(ftype)
      else:
        iprot.skip(ftype)
      iprot.readFieldEnd()
    iprot.readStructEnd()

  def write(self, oprot):
    if oprot.__class__ == TBinaryProtocol.TBinaryProtocolAccelerated and self.thrift_spec is not None and fastbinary is not None:
      oprot.trans.write(fastbinary.encode_binary(self, (self.__class__, self.thrift_spec)))
      return
    oprot.writeStructBegin('allow_result')
    if self.error is not None:
      oprot.writeFieldBegin('error', TType.STRUCT, 1)
      self.error.write(oprot)
      oprot.writeFieldEnd()
    oprot.writeFieldStop()
    oprot.writeStructEnd()

  def validate(self):
    return


  def __hash__(self):
    value = 17
    value = (value * 31) ^ hash(self.error)
    return value

  def __repr__(self):
    L = ['%s=%r' % (key, value)
      for key, value in self.__dict__.iteritems()]
    return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

  def __ne__(self, other):
    return not (self == other)
