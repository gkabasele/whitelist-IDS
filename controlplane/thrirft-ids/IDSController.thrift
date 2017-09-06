namespace py IDSControllerPy
namespace cpp IDSControllerCpp

exception IDSControllerException
{
    1: i32 error_code;
    2: string error_description
}

struct Flow {
    1: required string srcip
    2: required string dstip
    3: required i16    srcport
    4: required i16    dstport
    5: required byte   proto
    7: optional byte   funcode
    8: optional i16    length  
} 


service Controller
{
    void mirror (1: Flow req, 2:list<i16> switches) throws (1: IDSControllerException error)
    void redirect (1: Flow req, 2:list<i16> switches) throws (1: IDSControllerException error)
    void block (1: Flow req, 2:list<i16> switches) throws (1: IDSControllerException error)
    void allow (1: Flow req, 2:list<i16> switches) throws (1: IDSControllerException error)
}
