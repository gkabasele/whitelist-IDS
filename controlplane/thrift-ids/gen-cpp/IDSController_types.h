/**
 * Autogenerated by Thrift Compiler (0.9.2)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef IDSController_TYPES_H
#define IDSController_TYPES_H

#include <iosfwd>

#include <thrift/Thrift.h>
#include <thrift/TApplicationException.h>
#include <thrift/protocol/TProtocol.h>
#include <thrift/transport/TTransport.h>

#include <thrift/cxxfunctional.h>


namespace IDSControllerCpp {

class IDSControllerException;

class Flow;

typedef struct _IDSControllerException__isset {
  _IDSControllerException__isset() : error_code(false), error_description(false) {}
  bool error_code :1;
  bool error_description :1;
} _IDSControllerException__isset;

class IDSControllerException : public ::apache::thrift::TException {
 public:

  static const char* ascii_fingerprint; // = "3F5FC93B338687BC7235B1AB103F47B3";
  static const uint8_t binary_fingerprint[16]; // = {0x3F,0x5F,0xC9,0x3B,0x33,0x86,0x87,0xBC,0x72,0x35,0xB1,0xAB,0x10,0x3F,0x47,0xB3};

  IDSControllerException(const IDSControllerException&);
  IDSControllerException& operator=(const IDSControllerException&);
  IDSControllerException() : error_code(0), error_description() {
  }

  virtual ~IDSControllerException() throw();
  int32_t error_code;
  std::string error_description;

  _IDSControllerException__isset __isset;

  void __set_error_code(const int32_t val);

  void __set_error_description(const std::string& val);

  bool operator == (const IDSControllerException & rhs) const
  {
    if (!(error_code == rhs.error_code))
      return false;
    if (!(error_description == rhs.error_description))
      return false;
    return true;
  }
  bool operator != (const IDSControllerException &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const IDSControllerException & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  friend std::ostream& operator<<(std::ostream& out, const IDSControllerException& obj);
};

void swap(IDSControllerException &a, IDSControllerException &b);

typedef struct _Flow__isset {
  _Flow__isset() : funcode(false), length(false) {}
  bool funcode :1;
  bool length :1;
} _Flow__isset;

class Flow {
 public:

  static const char* ascii_fingerprint; // = "665054788FFD5C477ADDCB3717F4E112";
  static const uint8_t binary_fingerprint[16]; // = {0x66,0x50,0x54,0x78,0x8F,0xFD,0x5C,0x47,0x7A,0xDD,0xCB,0x37,0x17,0xF4,0xE1,0x12};

  Flow(const Flow&);
  Flow& operator=(const Flow&);
  Flow() : srcip(), dstip(), srcport(0), dstport(0), proto(0), funcode(0), length(0) {
  }

  virtual ~Flow() throw();
  std::string srcip;
  std::string dstip;
  int16_t srcport;
  int16_t dstport;
  int8_t proto;
  int8_t funcode;
  int16_t length;

  _Flow__isset __isset;

  void __set_srcip(const std::string& val);

  void __set_dstip(const std::string& val);

  void __set_srcport(const int16_t val);

  void __set_dstport(const int16_t val);

  void __set_proto(const int8_t val);

  void __set_funcode(const int8_t val);

  void __set_length(const int16_t val);

  bool operator == (const Flow & rhs) const
  {
    if (!(srcip == rhs.srcip))
      return false;
    if (!(dstip == rhs.dstip))
      return false;
    if (!(srcport == rhs.srcport))
      return false;
    if (!(dstport == rhs.dstport))
      return false;
    if (!(proto == rhs.proto))
      return false;
    if (__isset.funcode != rhs.__isset.funcode)
      return false;
    else if (__isset.funcode && !(funcode == rhs.funcode))
      return false;
    if (__isset.length != rhs.__isset.length)
      return false;
    else if (__isset.length && !(length == rhs.length))
      return false;
    return true;
  }
  bool operator != (const Flow &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const Flow & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  friend std::ostream& operator<<(std::ostream& out, const Flow& obj);
};

void swap(Flow &a, Flow &b);

} // namespace

#endif