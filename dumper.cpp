/* (C) 2003-2013 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *
 */
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <string>
#include <vector>

#include <boost/format.hpp>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

// headers from the idasdk
#include "pro.h"     // for basic types.
#include "ida.hpp"   // for ida constants and types.
#include "idp.hpp"   // for interface version
#include "dbg.hpp"   // for 'dbg' global variable
#include "netnode.hpp"  // for RootNode

#include "expr.hpp"  // for IDCFuncs

#if IDA_SDK_VERSION >= 700
typedef ext_idcfunc_t extfun_t;

struct funcset_t {
  int qnty;                     ///< Number of functions
  ext_idcfunc_t *f;                  ///< Function table
};
funcset_t *find_idcfuncs()
{
    uint64_t *p = (uint64_t*)&callui;
    uint64_t *pend = (uint64_t*)&dbg;
    p++;
    while (p<pend && *p==0)
        p++;
    uint64_t addr_fnlist = (uint64_t )p;

    while (p<pend) {
        if (0x100 < *p && *p < 0x1000) {
            if (p[1]!=addr_fnlist) {
                msg("expected to find addr list after count %lld\n", p[0]);
            }
            break;
        }
        if (*p==addr_fnlist) {
            msg("expected to find count %lld before fnlist\n", p[-1]);
            p--;
            break;
        }
        p++;
    }
    if (p==pend) {
        msg("could not find fset\n");
        return nullptr;
    }

    uint32_t *pd = (uint32_t *)(p+9);
#ifdef IDA70BETA3
    typedef size_t (*ea2str_fn)(ea_t ea, char *buf, size_t bufsize);
#else
    typedef size_t (*ea2str_fn)(char *buf, size_t bufsize, ea_t ea);
#endif

    msg("fnlist = %llx, ea2str = %llx\n", addr_fnlist, (uint64_t)ea2str_fn(ea2str));
    msg("found idcfuncs @%p: %lld,  %llx, %llx, %llx, %llx,  %lld,  %llx, %llx, %llx, %d, %d, %d, %d\n",
            p,  p[0],  p[1], p[2], p[3], p[4],  p[5],  p[6], p[7], p[8],  pd[0], pd[1], pd[2], pd[3]);
    return (funcset_t*)p;
}


// memlayout:
// _callui   = sub_...
// ext_idcfunc_t fnlist[0x1ef] = { { }, ... }
// funcset_t IDCFuncs { 0x1ef, fnlist, sub, sub, sub, 0, netnode_inited, ea2str, sub, (int)9, 10, 15, 18, 7 }
//

funcset_t dummyfuncs = {0, nullptr};
funcset_t &IDCFuncs = dummyfuncs;
#endif

typedef std::vector<char> CharVector;

typedef struct {
    char  *function_name;      // 00
    char  *end_function_name;  // 04
    uint32_t w1;                  // 08
    uint32_t w2;                  // 0c
    uint8_t *after_end_fnname;   // 10
    uint32_t w4;                  // 14
    uint32_t nrparams;            // 18
    uint8_t *body;               // 1c
    uint8_t *end_body;           // 20
    uint32_t w5;                  // 24
    uint32_t w6;                  // 28
    uint32_t w7;                  // 2c
    uint32_t w8;                  // 30
} compiled_func1_t;

typedef struct {
    char  *function_name;      // 00
    char  *end_function_name;  // 04
    uint32_t w1;                  // 08
    uint32_t w2;                  // 0c
    uint8_t *after_end_fnname;   // 10
    uint32_t w4;                  // 14
    uint32_t nrparams;            // 18
    uint8_t *body;               // 1c
    uint32_t bodysize;            // 20
    uint32_t w5;                  // 24
} compiled_func2_t;

// ida530 and later
typedef struct {
    char *function_name;
    uint32_t namelen;
    uint32_t namelen2;
    uint32_t nrparams;
    uint8_t *body;
    uint32_t bodysize;
    uint32_t roundedbodysize;
} compiled_func3_t;

typedef struct {
    uint32_t unk0;
    char *filename;
    uint32_t namelen;
    uint32_t name_alloced;
} srcfile4_t;
#undef PACKED
#ifdef _WIN32
#define PACKED
#pragma pack(push,1)
#else
#define PACKED __attribute__((packed))
#endif
typedef struct PACKED {
    uint32_t unk0;
    char *filename;
    uint64_t namelen;
    uint64_t name_alloced;
} srcfile6_t;
#undef PACKED
#ifdef _WIN32
#pragma pack(pop)
#else
#define PACKED __attribute__((packed))
#endif

typedef struct {
    uint32_t ofs;
    uint32_t linenr;
} linenr4_t;
typedef struct {
    char *function_name;
    uint32_t namelen;
    uint32_t name_alloced;
    uint32_t nrparams;
    uint8_t *body;
    uint32_t bodysize;
    uint32_t body_alloced;
    uint32_t ofs_lastinsn;
    srcfile4_t *srcfile;
    uint32_t nsrc;
    uint32_t src_alloced;
    linenr4_t *lineinfo;
    uint32_t nlines;
    uint32_t line_alloced;
} compiled_func4_t;

typedef compiled_func4_t compiled_func5_t;

typedef struct {
    char *function_name;
    uint64_t namelen;
    uint64_t name_alloced;

    uint64_t nrparams;

    uint8_t *body;
    uint64_t bodysize;
    uint64_t body_alloced;

    uint64_t ofs_lastinsn;

    srcfile6_t *srcfile;
    uint64_t nsrc;
    uint64_t src_alloced;

    linenr4_t *lineinfo;
    uint64_t nlines;
    uint64_t line_alloced;

    void *unkinfo;
    uint64_t unkcount;
    uint64_t unkalloc;
} compiled_func6_t;

typedef struct {
    char *function_name;
    uint64_t namelen;
    uint64_t name_alloced;

    uint64_t nrparams;

    uint8_t *body;
    uint64_t bodysize;
    uint64_t body_alloced;

    uint64_t ofs_lastinsn;

    srcfile6_t *srcfile;
    uint64_t nsrc;
    uint64_t src_alloced;

    linenr4_t *lineinfo;
    uint64_t nlines;
    uint64_t line_alloced;

    void *unkinfo;
    uint64_t unkcount;
    uint64_t unkalloc;

    uint64_t unknown;
} compiled_func7_t;



// !!! GLOBAL ... initialized by dump_compiled_functions
//   used by disassemble, to resolve compiled functions indexes.

compiled_func1_t *g_flist1;
compiled_func1_t *g_end1;
compiled_func2_t *g_flist2;
compiled_func2_t *g_end2;
compiled_func3_t *g_flist3;
compiled_func3_t *g_end3;
compiled_func4_t *g_flist4;
compiled_func4_t *g_end4;
compiled_func5_t **g_flist5;
compiled_func6_t **g_flist6;
compiled_func7_t **g_flist7;

int g_type=0;
std::string getcompiledname(int id)
{
    if (g_flist1)
        return g_flist1[id].function_name;
    else if (g_flist2)
        return g_flist2[id].function_name;
    else if (g_flist3)
        return g_flist3[id].function_name;
    else if (g_flist4)
        return g_flist4[id].function_name;
    else if (g_flist5)
        return g_flist5[id]->function_name;
    else if (g_flist6)
        return g_flist6[id]->function_name;
    else if (g_flist7)
        return g_flist7[id]->function_name;
    else
        return "unknown!!!";
}


std::string hexdump(const uint8_t *p, int len)
{
    if (p==NULL)
        return "(null)";
    std::string str;
    for (int i=0 ; i<len ; i++) {
        if (!str.empty()) str += " ";
        char strbuf[16];
        qsnprintf(strbuf, 16, "%02x", p[i]);

        str += strbuf;
    }
    return str;
}

std::string ascdump(const unsigned char *buf, size_t len)
{
    const std::string& escaped="\n\r\t";
    bool bBreakOnEol= false;
    std::string result;
    bool bQuoted= false;
    bool bLastWasEolChar= false;

    if (len==size_t(-1))
        return "(null)";
    if (len==0)
        return "\"\"";

    if (len==4)
        result = str(boost::format("[%08lx]") % *(const long*)buf);

    for (size_t i=0 ; i<len ; i++)
    {
        bool bNeedsEscape= escaped.find((char)buf[i])!=escaped.npos 
            || buf[i]=='\"' 
            || buf[i]=='\\';

        if (isprint(buf[i]) || bNeedsEscape) {
            if (!bQuoted) {
                if (!result.empty())
                    result += ",";
                result += "\"";
                bQuoted= true;
            }
            if (bNeedsEscape) {
                std::string escapecode;
                switch(buf[i]) {
                    case '\n': escapecode= "\\n"; break;
                    case '\r': escapecode= "\\r"; break;
                    case '\t': escapecode= "\\t"; break;
                    case '\"': escapecode= "\\\""; break;
                    case '\\': escapecode= "\\\\"; break;
                    default:
                       escapecode = str(boost::format("\\x%02x") % (((unsigned int)buf[i])&0xff));
                }
                result += escapecode;
            }
            else {
                result += (char) buf[i];
            }
        }
        else {
            if (bQuoted) {
                result += "\"";
                bQuoted= false;
            }
            if (!result.empty())
                result += ",";
            result += str(boost::format("%02x") % (int)buf[i]);
        }
        bool bThisIsEolChar= (buf[i]==0x0a || buf[i]==0x0d);

        if (bLastWasEolChar && !bThisIsEolChar && bBreakOnEol)
            result += "\n";

        bLastWasEolChar= bThisIsEolChar;
    }

    if (bQuoted) {
        result += "\"";
        bQuoted= false;
    }

    return result;
}
std::string tagstr(char tag)
{
    if (tag>=' ' && tag<='~') {
        char strbuf[2];
        strbuf[0]= tag;
        strbuf[1]= 0;
        return std::string(strbuf);
    }
    else {
        char strbuf[16];
        qsnprintf(strbuf, 16, "%02x", (uint8_t)tag);
        return std::string(strbuf);
    }
}
std::ostream& operator<<(std::ostream& os, nodeidx_t idx)
{
    return os << boost::format("%08lx") % ((int)idx);
}
#if IDP_INTERFACE_VERSION<76
std::ostream& operator<<(std::ostream& os, netnode& node)
{
    os << boost::format("node %08lx ll=%d  %s\n") 
            % ((nodeidx_t)node) 
            % node.last_length()
            % (node.name()?node.name():"(null)");

    if (node.value_exists()) {
        os << boost::format("long_value: %08lx str=%s\n") 
            % ascdump((unsigned char*)node.value(), MAXSPECSIZE);
    }
    else {
        os << "no value\n";
    }
    for (int tag= 0 ; tag < 0x100 ; tag++)
        for (nodeidx_t idx= node.supfirst(tag) ; idx!=BADNODE ; idx= node.supnext(idx, tag))
        {
            os << boost::format("[%s, %08lx] : alt=%08lx ch=%02x sup=%s\n") 
                    % tagstr(tag) % idx
                    % node.altval(idx, tag)
                    % ((int)node.charval(idx, tag))
                    % ascdump((unsigned char*)node.supval(idx, tag), MAXSPECSIZE);
        }
/*
    for (int tag=0 ; tag<0x100 ; tag++)
        for (char* idx= node.hashfirst(tag) ; idx ; idx=node.hashnext(idx, tag))
            os << boost::format("hashval(%s, %s) : %s\n")
                    % tagstr(tag) % idx
                    % (node.hashval(idx, tag)?node.hashval(idx, tag):"(null)");
*/
/* ... netlink is missing from ida.lib
    netlink l;
    if (l.start())
        os << boost::format("listing links of type %s\n") % l.name();
        do {
            for (netnode n= l.firstlink(node); n!=BADNODE ; n= l.nextlink(node, n)) {
                os << boost::format("  link to %08lx %s\n") % (nodeidx_t)n % n.name();
            }
        } while (l.next());
*/
    return os;
}
#else   // idp >= 76
std::ostream& operator<<(std::ostream& os, netnode& node)
{
	qstring name;
    char buf[MAXSPECSIZE];

    node.get_name(&name);

	os << boost::format("node %08lx %s %s\n") 
            % ((nodeidx_t)node) 
            % ascdump((const uint8_t*)name.c_str(), name.size())
            % ascdump((unsigned char*)buf, node.valobj(buf, MAXSPECSIZE));

    for (int tag= 0 ; tag < 0x100 ; tag++)
        for (nodeidx_t idx= node.supfirst(tag) ; idx!=BADNODE ; idx= node.supnext(idx, tag))
        {
            os << boost::format("[%s, %08lx] : %s\n") 
                    % tagstr(tag) % idx
                    % ascdump((unsigned char*)buf, node.supval(idx, buf, MAXSPECSIZE, tag));
        }

	for (int tag=0 ; tag<0x100 ; tag++) {

        // use two alternating buffers for comparing if we are still moving forward with 'H'
		char idx[2][1024];
        int hs[2];  hs[0]=0; hs[1]=0;
		int i=0;
        memset(idx, 0, sizeof(idx));
		for (hs[i]= node.hashfirst(idx[i], 1024, tag) ; hs[i]>0 ; hs[i]=node.hashnext(idx[i^1], idx[i], 1024, tag)) {
            if (hs[0]==hs[1] && memcmp(idx[0], idx[1], hs[0])==0)
                break;
            i ^= 1;

            if (node.supval(*(sval_t*)idx[i^1], NULL, 0, tag)<0)
                os << boost::format("hashval(%s, %s) : %s\n")
                    % tagstr(tag) % ascdump((unsigned char*)idx[i^1], hs[i^1])
                    % ascdump((unsigned char*)buf, node.hashval(idx[i^1], buf, MAXSPECSIZE, tag));
		}
	}

/* ... netlink is missing from ida.lib
    netlink l;
    if (l.start())
        os << boost::format("listing links of type %s\n") % l.name();
        do {
            for (netnode n= l.firstlink(node); n!=BADNODE ; n= l.nextlink(node, n)) {
                os << boost::format("  link to %08lx %s\n") % (nodeidx_t)n % n.name();
            }
        } while (l.next());
*/
    return os;
}
#endif
std::string functionargs_string(const char *args)
{
    std::string str;
    if (args==NULL) 
        return "(null)";
    while (*args) {
        if (!str.empty()) str += ", ";
        switch(*args)
        {
            case VT_STR:   str += "string"; break;
            case VT_LONG:  str += "long"; break;
            case VT_FLOAT: str += "float"; break;
            case VT_WILD:  str += "..."; break;
#ifdef VT_OBJ
            case VT_OBJ:   str += "object"; break;
            case VT_FUNC:  str += "function"; break;
#ifdef VT_STR2
            case VT_STR2:  str += "string2"; break;
#endif
            case VT_PVOID: str += "pvoid"; break;
            case VT_INT64: str += "int64"; break;
            case VT_REF:   str += "vref"; break;
#endif
            default: 
               char strbuf[16];
               qsnprintf(strbuf, 16, "VT_%08x", *args);
               str += strbuf;
        }

        args++;
    }
    return str;
}
std::string escapestring(const std::string& ascstr)
{
    std::string esc;
    for (std::string::const_iterator i= ascstr.begin() ; i!=ascstr.end() ; ++i) {
             if ((*i)=='\n') esc += "\\n";    // 0x0a newline
        else if ((*i)=='\r') esc += "\\r";    // 0x0d carriage return
        else if ((*i)=='\t') esc += "\\t";    // 0x09 tab
        else if ((*i)=='\\') esc += "\\\\";   // 0x5c backslash
        else if ((*i)=='\v') esc += "\\v";    // 0x0b vertical tab
        else if ((*i)=='\b') esc += "\\b";    // 0x08 backspace
        else if ((*i)=='\f') esc += "\\f";    // 0x0c form feed
        else if ((*i)=='\a') esc += "\\a";    // 0x07 bell
        else if ((*i)=='\"') esc += "\\\"";   // 0x22 double quote
        else if (isprint(*i))
            esc += (*i);
        else
            esc += str(boost::format("\\x%02x") % (((unsigned int)(*i))&0xff));
    }
    return esc;
}


uint16_t get16le(const uint8_t *p) { return p[0] | (p[1]<<8); }
uint32_t get32le(const uint8_t *p) { return get16le(p) | (get16le(p+2)<<16); }
uint64_t get64le(const uint8_t *p) { return get32le(p) | (uint64_t(get32le(p+4))<<32); }

// ida5.40 has the idc bytecode dispatcher table at ida.wll : 100D5703
void disassemble(std::ostream&os, const uint8_t *body, int len)
{
    for (int i=0 ; i<len ; i++)
    {
        os << boost::format("%p %04x  %02x")
            % (void*)(body+i)
            % i
            % ((int)body[i]);

        // nyble and byte must be 'int'  to make boostformat choose the right representation
        int nyble = body[i]&0xf;
        int byte  = (i+1<len)?body[i+1] : 0;
        uint16_t word  = (i+2<len)?get16le(&body[i+1]):0;
        uint32_t dword = (i+4<len)?get32le(&body[i+1]):0;
        uint64_t qword = (i+8<len)?get64le(&body[i+1]):0;

        switch(body[i]&0xf0) {
            case 0x00: // call internfunc 00-0f
                os << boost::format("          ; call %04x %s\n")
                    % nyble
                    % IDCFuncs.f[nyble].name;
                break;
            case 0x10: // call userdef func 00-0f
                os << boost::format("          ; call compiled func %02x %s\n")
                    % nyble
                    % getcompiledname(nyble);
                break;
            case 0x20: // pop var 00-0f
                os << boost::format("          ; pop var%02x\n")
                    % nyble;
                break;
            case 0x30: // pop param 00-0f
                os << boost::format("          ; pop param%02x\n")
                    % nyble;
                break;
            case 0x40: // var 00-0f = tos
                os << boost::format("          ; var%02x := tos\n")
                    % nyble;
                break;
            case 0x50: // param 00-0f = tos
                os << boost::format("          ; param%02x := tos\n")
                    % nyble;
                break;
            case 0x60: // push var 00-0f
                os << boost::format("          ; push var%02x\n")
                    % nyble;
                break;
            case 0x70: // push param 00-0f
                os << boost::format("          ; push param%02x\n")
                    % nyble;
                break;
            // case 0x80: these are handled in default:
            // case 0x90: unused
            // case 0xa0: these are handled in default:
            // case 0xb0: these are handled in default:
            // case 0xc0: these are handled in default:
            // case 0xd0: these are handled in default:
            case 0xe0:
                os << boost::format("          ; push #%02x\n")
                    % nyble;
                break;
            // case 0xf0: handled by default

            // handle non nyble oriented opcodes
            default: switch(body[i]) {
            case 0x80:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; call %04x %s\n")
                    % byte
                    % byte
                    % IDCFuncs.f[byte].name;
                i++;
                break;
            case 0x81:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                if (word>=IDCFuncs.qnty) { os << boost::format("\nERROR: too large internal funcid: %04x\n") % word; break; }
                os << boost::format(" %04x     ; call %04x %s\n")
                    % word
                    % word
                    % IDCFuncs.f[word].name;
                i += 2;
                break;
            case 0x82:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; call compiled func %02x %s\n")
                    % byte
                    % byte
                    % getcompiledname(byte);
                i++;
                break;
            case 0x83:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; call compiled func %04x %s\n")
                    % word
                    % word
                    % getcompiledname(word);
                i += 2;
                break;
            case 0x84:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; pop var%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0x85:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; pop var%04x\n")
                    % word
                    % word;
                i += 2;
                break;
            case 0x86:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; param%02x := tos\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0x87:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; param%04x := tos\n")
                    % word
                    % word;
                i += 2;
                break;
            case 0x88:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; var%02x := tos\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0x89:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; var%04x := tos\n")
                    % word
                    % word;
                i += 2;
                break;
            case 0x8a:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; pop param%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0x8b:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; pop param%04x\n")
                    % word
                    % word;
                i += 2;
                break;
            case 0x8c:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; push var%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0x8d:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; push var%04x\n")
                    % word
                    % word;
                i += 2;
                break;
            case 0x8e:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; push param%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0x8f:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x       ; push param%04x\n")
                    % word
                    % word;
                i += 2;
                break;
            // 0x90 is unused
            case 0xa0:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code (i=%d, l=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; push #%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0xa1:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; push #%04x\n")
                    % word
                    % word;
                i+=2;
                break;
            case 0xa2:  // todo: figure this one out
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; unknown %02x\n")
                    % byte
                    % byte;
                i++;
                break;

            case 0xa3: // todo: figure this one out
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; unknown %04x\n")
                    % word
                    % word;
                i+=2;
                break;

            case 0xa4:
                if (g_type<=3) {
                    if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                    os << boost::format(" %02x       ; allocate %d local variables\n")
                        % byte
                        % byte;
                    i++;
                }
                else {
                    os << boost::format("          ; invoke fucntion reference\n");
                }
                break;
            case 0xa5:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; allocate %d local variables\n")
                    % word
                    % word;
                i+=2;
                break;

            // a6 is probably NOP
            case 0xa6: os << boost::format("          ; unknown\n"); break;
            case 0xa7:
                if (i >= len-4) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %08x ; push #%08x\n")
                    % dword
                    % dword;
                i+=4;
                break;
            case 0xa8:
                if (i >= len-2-word) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x ... ; push \"%s\"\n")
                    % word
                    % escapestring(std::string((char*)body+i+3, word)).c_str();
                i+=word+2;
                break;
            case 0xa9:
                os << boost::format("          ; pop\n");
                break;
            case 0xaa:
                os << boost::format("          ; start function param list\n");
                break;
            case 0xab:
                if (i >= len-4) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %08x ; branch always %08x -> %04x\n")
                    % dword
                    % dword
                    % (i+dword+5);
                i+=4;
                break;
            case 0xac:
                if (i >= len-4) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %08x ; branch do_while true %08x -> %04x\n")
                    % dword
                    % dword
                    % (i+dword+5);
                i+=4;
                break;
            case 0xad:
                if (i >= len-4) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %08x ; branch if true %08x -> %04x\n")
                    % dword
                    % dword
                    % (i+dword+5);
                i+=4;
                break;
            case 0xae:
                if (g_type<=3) {
                    if (i >= len-2-word) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                    os << boost::format(" %04x ... ; call by name \"%s\"\n")
                        % word
                        % escapestring(std::string((char*)body+i+3, word)).c_str();
                    i+=word+2;
                }
                else {
                    if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                    if (byte==0xa4)
                        os << boost::format("%02x        ; call by name\n") % byte;
                    else if (byte==0x40)
                        os << boost::format("%02x        ; create function reference\n") % byte;
                    else
                        os << boost::format(" %02x       ; unknown\n") % byte;
                    i+=1;
                }
                break;
            case 0xaf: 
                os << boost::format("          ; return\n");
                break;
            case 0xb0: os << boost::format("          ; add\n"); break;
            case 0xb1: os << boost::format("          ; substract\n"); break;
            case 0xb2: os << boost::format("          ; multiply\n"); break;
            case 0xb3: os << boost::format("          ; divide\n"); break;
            case 0xb4: os << boost::format("          ; modulus\n"); break;
            case 0xb5: os << boost::format("          ; logical or\n"); break;
            case 0xb6: os << boost::format("          ; logical and\n"); break;
            case 0xb7: os << boost::format("          ; logical not\n"); break;
            case 0xb8: os << boost::format("          ; bitwise or\n"); break;
            case 0xb9: os << boost::format("          ; bitwise and\n"); break;
            case 0xba: os << boost::format("          ; bitwise xor\n"); break;
            case 0xbb: os << boost::format("          ; unary bitwise negate\n"); break;
            case 0xbc: os << boost::format("          ; shiftright\n"); break;
            case 0xbd: os << boost::format("          ; shiftleft\n"); break;
            case 0xbe: os << boost::format("          ; unary minus\n"); break;
            case 0xbf: os << boost::format("          ; cv to string2\n"); break;
            case 0xc0:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; increment var%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0xc1:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; increment var%04x\n")
                    % word
                    % word;
                i += 2;
                break;
            case 0xc2:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; increment param%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0xc3:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; increment param%04x\n")
                    % word
                    % word;
                i+=2;
                break;
            case 0xc4:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; decrement var%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0xc5:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; decrement var%04x\n")
                    % word
                    % word;
                i+=2;
                break;
            case 0xc6:
                if (i >= len-1) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %02x       ; decrement param%02x\n")
                    % byte
                    % byte;
                i++;
                break;
            case 0xc7:
                if (i >= len-2) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
                os << boost::format(" %04x     ; decrement param%04x\n")
                    % word
                    % word;
                i+=2;
                break;
            case 0xc8: os << boost::format("          ; compare ==\n"); break;
            case 0xc9: os << boost::format("          ; compare !=\n"); break;
            case 0xca: os << boost::format("          ; compare <=\n"); break;
            case 0xcb: os << boost::format("          ; compare >=\n"); break;
            case 0xcc: os << boost::format("          ; compare <\n"); break;
            case 0xcd: os << boost::format("          ; compare >\n"); break;
            case 0xce: os << boost::format("          ; cv to integer\n"); break;
            case 0xcf: os << boost::format("          ; cv to string\n"); break;
            case 0xd0: os << boost::format("          ; cv to float\n"); break;
            case 0xd1: os << boost::format("          ; ?????\n"); break;
//              if (i >= len-12) { os << boost::format("\nERROR: unexpected end of code(i=%d, len=%d, opc=%02x)\n") %i %len %((int)body[i]); break; }
//              os << boost::format(" .......... ; push float %s\n")
//                  % hexdump(body+i+1, 12);
//              i+=12;

            // 0xd2 is unused
            case 0xd3: os << boost::format(" %09llx; push #%016llx\n") % qword % qword; i+=8; break;
            case 0xd4: os << boost::format(" %02x       ; push global %02x\n") % byte % byte; i+=1; break;
            case 0xd5: os << boost::format(" %04x     ; push global %04x\n") % word % word; i+=2; break;
            case 0xd6: os << boost::format(" %02x       ; pop global %02x\n") % byte % byte; i+=1; break;

            case 0xd7: os << boost::format(" %04x     ; pop global %04x\n") % word % word; i+=2; break;

                       // todo: d7 e101  -> set global eq to 01
                       //       d7 e000  -> set global eq to tos

                       // probably  global = tos
            case 0xd8: os << boost::format("          ; unknown\n"); break; // todo: figure this one out
            case 0xd9: os << boost::format("          ; unknown\n"); break; // todo: figure this one out
            case 0xda: os << boost::format(" %02x       ; inc global %02x\n") % byte % byte; i+=1; break;
            case 0xdb: os << boost::format(" %04x     ; inc global %04x\n") % word % word; i+=2; break;
            case 0xdc: os << boost::format(" %02x       ; dec global %02x\n") % byte % byte; i+=1; break;
            case 0xdd: os << boost::format(" %04x     ; dec global %04x\n") % word % word; i+=2; break;
            // case 0xde:  unused
            case 0xdf: os << boost::format("          ; throw\n"); break;
            case 0xf0:
                       os << boost::format(" %04x     ; create object %04x\n") % word % word;
                       // todo: decode object type
                       i+=2;
                       break;
            // case 0xf1: ...
            case 0xf2: os << boost::format("          ; get object property\n"); break;
            case 0xf4: os << boost::format("          ; set object property\n"); break;
            case 0xf5: os << boost::format("          ; increment object property\n"); break;
            case 0xf7: os << boost::format("          ; method call\n"); break;
            case 0xf8: os << boost::format("          ; ???object ref???\n"); break;
            case 0xf9: os << boost::format("          ; create reference\n"); break;
            // 0xfa
            case 0xfb: os << boost::format("          ; set slice\n"); break;
            case 0xfc: os << boost::format("          ; get slice\n"); break;
            // 0xfd
            case 0xfe: os << boost::format("          ; get item at\n"); break;
            case 0xff: os << boost::format("          ; set item at\n"); break;
            default:
                os << boost::format("            ; ERROR: unused opcode\n");
             }
        }
    }
}
void funcbody(std::ostream&os, const char *name)
{

#if (IDP_INTERFACE_VERSION>=70) && (IDA_SDK_VERSION<700)
    int nargs=0;
    size_t bodylen=0;
// get_idc_func_body is only available since version 4.70
    uint8_t *body= get_idc_func_body(name, &nargs, &bodylen);
    if (body)
    {
        os << boost::format("body: %08lx-%08lx: %s(%d)\n")
            % ((int)body)
            % ((int)body+bodylen)
            % name
            % nargs;
        disassemble(os, body, bodylen);
        os << "\n";
    }
#endif
}
std::ostream& operator<<(std::ostream& os, const extfun_t& f)
{
    funcbody(os, f.name);

#if IDP_INTERFACE_VERSION>70
    return os << boost::format("fu=%08llx fl=%08lx %s(%s)")
        % ((uint64_t)f.fptr)
        % f.flags
        % (f.name ? f.name : "(null)")
        % functionargs_string(f.args);
#else
    // no 'flags' in ida 4.70 and earlier
    return os << boost::format("fu=%08lx %s(%s)")
        % ((int)f.fp)
        % f.name
        % functionargs_string(f.args);

#endif
}
std::ostream& operator<<(std::ostream& os, funcset_t& fset)
{
    os << boost::format("%d functions in set %08lx\n") % fset.qnty % (long)&fset;
    for (int i=0 ; i<fset.qnty ; i++) {
        os << boost::format("function %d : %s\n") % i % fset.f[i];
    }
    return os;
}

/*idp = IDP_INTERFACE_VERSION
 *
 *  these are all offsets in ida.wll ( or ida64.wll )
 *
 *  for recent versions, the ptr is between the string '(null)' and 'funcbody_t:'
 *
 *idp              IDCFuncs   compiled    IDCFuncs64  exe version
 * 61 ida430a      100b76b8                     
 * 63 ida450       1009ad8c                     
 * 66 ida460       100b31e4                           4.06.0000.0785
 * 67 ida460sp1    100b5224                           4.06.0000.0809
 * 70 ida470       100baaf3   100db2bc                4.07.0000.0830
 *  ?                         100ec1b0               
 * 75 ida480       100bf3c0   100F3CCC                4.08.0000.0847
 *  ? ida48991
 *  ? ida48992
 *  ? ida48993
 *  ? ida48994
 *  ? ida48995     100E13AC                           4.08.0001.0849
 * 76 ida490       100d3748   101019C0    100E6748    4.09.0000.0863
 * 76 ida490sp1    100e9778   1011c2c0    10104778    4.09.0000.0877
 * 76 ida500       100eb778   1011e880    10106778    5.00.0000.0879
 * 76 ida510b2     100f9a44               10116A44    
 * 76 ida510       100f9f44   1012a860    10116F44    5.01.0000.0899
 * 76 ida520       1010837a   10136ef0                5.02.0000.0908
 * 76 ida520       10103116   101310C0                update
 * ??              1010a63e   10137224               
 * ?? ida530       100ff4d3   1012bfa0?               5.3.0.916
 * ?? ida540b1     101164f3   10146e2c?               5.4.0.920
 *    ida570       10139fff   1016E550
 */ 
typedef struct {
    compiled_func1_t *start;
    compiled_func1_t *end;
} listinfo1_t;
typedef struct {
    compiled_func2_t *start;
    uint32_t count;
} listinfo2_t;
typedef struct {
    compiled_func3_t *start;
    uint32_t count;
} listinfo3_t;
typedef struct {
    compiled_func4_t *start;
    uint32_t count;
} listinfo4_t;
typedef struct {
    compiled_func5_t **start;
    uint32_t count;
} listinfo5_t;
typedef struct {
    compiled_func6_t **start;
    uint64_t count;
} listinfo6_t;
typedef struct {
    compiled_func7_t **start;
    uint64_t count;
} listinfo7_t;






void dump_idc_funcs1(std::ostream& os, listinfo1_t *flist)
{
    g_flist1= flist->start;
    g_end1= flist->end;
    for (compiled_func1_t *f= g_flist1 ; f<g_end1 ; f++) {
        os << boost::format("body: %08llx-%08llx: %s(%d)\n")
            % ((uint64_t)f->body)
            % ((uint64_t)f->end_body)
            % f->function_name
            % ((int)f->nrparams);
        disassemble(os, f->body, f->end_body-f->body);
    }
}

void dump_idc_funcs2(std::ostream& os, listinfo2_t *flist)
{
    g_flist2= flist->start;
    g_end2= flist->start+flist->count;
    for (compiled_func2_t *f= g_flist2 ; f<g_end2 ; f++) {
        os << boost::format("body: %08llx-%08llx: %s(%d)\n")
            % ((uint64_t)f->body)
            % (((uint64_t)f->body)+f->bodysize)
            % f->function_name
            % ((int)f->nrparams);
        disassemble(os, f->body, f->bodysize);
    }
}
void dump_idc_funcs3(std::ostream& os, listinfo3_t *flist)
{
    g_flist3= flist->start;
    g_end3= flist->start+flist->count;
    for (compiled_func3_t *f= g_flist3 ; f<g_end3 ; f++) {
        os << boost::format("body: %08llx-%08llx: %s(%d)\n")
            % ((uint64_t)f->body)
            % (((uint64_t)f->body)+f->bodysize)
            % f->function_name
            % ((int)f->nrparams);
        disassemble(os, f->body, f->bodysize);
    }
}
void dump_idc_funcs4(std::ostream& os, listinfo4_t *flist)
{
    g_flist4= flist->start;
    g_end4= flist->start+flist->count;
    for (compiled_func4_t *f= g_flist4 ; f<g_end4 ; f++) {
        os << boost::format("body: %08llx-%08llx: rec=%p  %s(%d)\n")
            % ((uint64_t)f->body)
            % (((uint64_t)f->body)+f->bodysize)
            % f
            % f->function_name
            % ((int)f->nrparams);
        disassemble(os, f->body, f->ofs_lastinsn);
        if (f->body) {
            os << "extra: ";
            os << hexdump(f->body+f->ofs_lastinsn, f->bodysize-f->ofs_lastinsn);
            os << "\n";
        }
    }
}
void dump_idc_funcs5(std::ostream& os, listinfo5_t *flist)
{
    g_flist5= flist->start;
    for (unsigned i=0 ; i<flist->count ; i++) {
        compiled_func5_t *f= flist->start[i];
        os << boost::format("body: %08llx-%08llx: rec=%p  %s(%d)\n")
            % ((uint64_t)f->body)
            % (((uint64_t)f->body)+f->bodysize)
            % f
            % f->function_name
            % ((int)f->nrparams);
        if (f->body) {
            disassemble(os, f->body, f->ofs_lastinsn);
            os << "extra: ";
            os << hexdump(f->body+f->ofs_lastinsn, f->bodysize-f->ofs_lastinsn);
            os << "\n";
        }
    }
}
void dump_idc_funcs6(std::ostream& os, listinfo6_t *flist)
{
    g_flist6= flist->start;
    for (unsigned i=0 ; i<flist->count ; i++) {
        compiled_func6_t *f= flist->start[i];
        os << boost::format("body: %08llx-%08llx: rec=%p  %s(%d)\n")
            % ((uint64_t)f->body)
            % (((uint64_t)f->body)+f->bodysize)
            % f
            % f->function_name
            % ((int)f->nrparams);
        if (f->body) {
            disassemble(os, f->body, f->ofs_lastinsn);
            os << "extra: ";
            os << hexdump(f->body+f->ofs_lastinsn, f->bodysize-f->ofs_lastinsn);
            os << "\n";
        }
    }
}
void dump_idc_funcs7(std::ostream& os, listinfo7_t *flist)
{
	msg("fn7: plist=%p, list: %p, count=%d\n", flist, flist->start, flist->count);
    g_flist7= flist->start;
    for (unsigned i=0 ; i<flist->count ; i++) {
        compiled_func7_t *f= flist->start[i];
        os << boost::format("body: %08llx-%08llx: rec=%p  %s(%d)\n")
            % ((uint64_t)f->body)
            % (((uint64_t)f->body)+f->bodysize)
            % f
            % f->function_name
            % ((int)f->nrparams);
        if (f->body) {
            disassemble(os, f->body, f->ofs_lastinsn);
            os << "extra: ";
            os << hexdump(f->body+f->ofs_lastinsn, f->bodysize-f->ofs_lastinsn);
            os << "\n";
        }
    }
}

std::string getkernelversion()
{
    char kversion[16];
    if (get_kernel_version(kversion, 16)) 
    {
        kversion[15] = 0;
        return kversion;
    }
    return "";
}

void dump_idc_funcs(std::ostream& os)
{
    std::string kernelversion = getkernelversion();
    
    uint64_t listptr= 0;
    g_type=0;
    switch((uint64_t)&IDCFuncs) {

//=========== windows versions of ida ====================
//case 0x100b76b8: flist=(listinfo_t*) 0; break;
//case 0x1009ad8c: flist=(listinfo_t*) 0; break;
//case 0x100b31e4: flist=(listinfo_t*) 0; break;
//case 0x100b5224: flist=(listinfo_t*) 0; break;
case 0x100baaf3: g_type=1; listptr= 0x100db2bc; break; //ida4.70 // ?? 0x100EC1B0;
case 0x100bf3c0: g_type=1; listptr= 0x100F3CCC; break; //ida4.80
case 0x100d3748: g_type=1; listptr= 0x101019C0; break; //ida4.90       - RootNode+0x0014   ida490/ida.wll

case 0x100e9778: g_type=1; listptr= 0x1011c2c0; break; //ida4.90sp1    - RootNode+0x0014   ida490_std/ida.wll, ida490sp1/ida.wll
case 0x100eb778: g_type=1; listptr= 0x1011e880; break; //ida5.00       - RootNode+0x0220   ida500/ida.wll
case 0x100f9f44: g_type=1; listptr= 0x1012a860; break; //ida5.10       - RootNode+0x00f4   ida510/ida.wll
//case 0x100f9a44: g_type=1; listptr= 0; break;
case 0x1010837a: g_type=2; listptr= 0x10136ef0; break; //ida5.20
case 0x10103116: g_type=2; listptr= 0x101310C0;        //ida5.20 update
                 if (*(uint64_t*)listptr==0) listptr= 0x101310AC; // ??
                 break;
case 0x1010a63e: g_type=2; listptr= 0x10137224; break; // ??
case 0x100ff4d3: g_type=3; listptr= 0x1012bfa0; break; // ida5.30      - RootNode+0x00f4   ida530/ida.wll
case 0x101164f3: g_type=3; listptr= 0x10146e2c; break; // ida5.40b1    - RootNode+0x0100   ida540b1/ida.wll
case 0x1011e1ef: g_type=3; listptr= 0x1014df14; break; // ida5.40      - RootNode+0x0100   ida540/ida.wll
case 0x1010f217: g_type=3; listptr= 0x101376b8; break; // ida5.50      - RootNode+0x00e0   ida550/ida.wll
case 0x1012db1b: g_type=4; listptr= 0x101608D4; break; // ida5.60      - RootNode+0x00f0   ida560_effe/ida.wll
case 0x10139fff: g_type=4; listptr= 0x1016E550; break; // ida5.70

                 // _RootNode + 0x20

//=========== macosx versions of ida ====================
case 0x00424880: g_type=5; listptr= 0x0043541c; break; // ida/mac 6.00.101001
case 0x00435880: g_type=5; listptr= 0x0044641c; break; // ida/mac 6.00.101104

case 0x004f3860: g_type=5; listptr= 0x00504fb0; break; // ida/mac 6.01.110408
// search for / 0[^0]0* 0*9 0*9 0*3 /  ( for _idcfunc entry )

// case 0x004f1b40: g_type=5; listptr= 0x00504fb0; break; // ida/mac 6.1.??
//
// .. preceeded by <d n="Output window" ... 
//
case 0x005508c0: g_type=5; listptr= 0x00561c90; break; // ida/mac 6.2
case 0x005788c0: g_type=5; listptr= 0x00580c30; break; // ida/mac 6.3
case 0x005aa8c0: g_type=5; listptr= 0x005b2e0c; break; // ida/mac 6.4
case 0x005ac8c0: g_type=5; listptr= 0x005b4e0c; break; // ida/mac 6.4.1

case 0x007978c0: g_type=5; listptr= 0x0079f67c; break; // ida/mac 6.5
case 0x006688c0: g_type=5; listptr= 0x0067067c; break; // ida/mac 6.5.1
//case 0x0079d8c0: g_type=5; listptr= ; break; // ida/mac 6.5.1+
case 0x006233c0: g_type=5; listptr= 0x00629260; break; // ida 6.7
case 0x006453e0: g_type=5; listptr= 0x0064b2c0; break; // ida 6.8
case 0x006463e0: g_type=5; listptr= 0x0064c2c0; break; // ida 6.8.1
case 0x006824a0: g_type=5; listptr= 0x006883a0; break; // ida 6.9
case 0x0068b4a0: g_type=5; listptr= 0x006913c0; break; // ida 6.9.5
case 0x007b54a0: g_type=5; listptr= 0x007BB3C0; break; // ida 6.9.5
    }
    uint32_t lowbits_IDCFunc = ((uint64_t)&IDCFuncs)&0xFFF;
    if (kernelversion == "6.95" && lowbits_IDCFunc == 0x4A0) {
        g_type = 5;
        listptr = 0x5F20 + ((uint64_t)&IDCFuncs);
    }
    else if (kernelversion == "7.00" /*&& lowbits_IDCFunc == 0xdb8*/) {
        g_type = 6;
        listptr = 0x1E8 + ((uint64_t)&root_node);

        msg("v70: idcfuncs=%llx -> list=%llx\n", ((uint64_t)&IDCFuncs), listptr);
    }
    else if (kernelversion == "7.1" /*&& IDCFunc == 0x100729f00, ea2str = 1004e1020 */) {
        g_type = 6;
        listptr = 0x1E8 + ((uint64_t)&root_node);

        msg("v71: idcfuncs=%llx -> list=%llx\n", ((uint64_t)&IDCFuncs), listptr);
    }
    else if (kernelversion == "7.2" ) {
        g_type = 7;
        listptr = -0x88 + ((uint64_t)&root_node);

        msg("v72: idcfuncs=%llx -> list=%llx\n", ((uint64_t)&IDCFuncs), listptr);
    }
    else if (kernelversion == "7.4" ) {
        g_type = 7;
        listptr = -0x88 + ((uint64_t)&root_node);
        msg("v74: idcfuncs=%llx -> list=%llx\n", ((uint64_t)&IDCFuncs), listptr);
    }
    else if (kernelversion == "7.6" ) {
        g_type = 8;

        listptr = -0x3C40 + ((uint64_t)&root_node);
        msg("v76: idcfuncs=%llx -> list=%llx\n", ((uint64_t)&IDCFuncs), listptr);
    }
    else if (kernelversion == "8.3" ) {
        g_type = 8;

        listptr = -0x25c8 + ((uint64_t)&root_node);
        msg("v83: idcfuncs=%llx -> list=%llx\n", ((uint64_t)&IDCFuncs), listptr);
    }




    if (listptr==0) {
        msg("IDCFuncs unknown: %p, kernelversion=%s\n", &IDCFuncs, kernelversion.c_str() );
        msg("  idcfuncs.qnty = %p, dummy = %p, rootnode = %p\n", &IDCFuncs.qnty, &dummyfuncs, &root_node);
        return;
    }
    if (g_type==1)
        dump_idc_funcs1(os, (listinfo1_t *)listptr);
    else if (g_type==2)
        dump_idc_funcs2(os, (listinfo2_t *)listptr);
    else if (g_type==3)
        dump_idc_funcs3(os, (listinfo3_t *)listptr);
    else if (g_type==4)
        dump_idc_funcs4(os, (listinfo4_t *)listptr);
    else if (g_type==5)
        dump_idc_funcs5(os, (listinfo5_t *)listptr);
    else if (g_type==6)
        dump_idc_funcs6(os, (listinfo6_t *)listptr);
    else if (g_type==7)
        dump_idc_funcs7(os, (listinfo7_t *)listptr);
    else if (g_type==8)
        dump_idc_funcs7(os, *(listinfo7_t **)listptr);
	else
		msg("unk type: %d\n", g_type);
}


void dump_db(int flags)
{
    std::filebuf fb; fb.open("dump_db.log", std::ios::out);
    std::ostream os(&fb);

    if (flags&1) {
        os << "------------rootnode-----------\n";
        os << root_node;

        os << "------------node.start.next-----------\n";
        netnode n; 
        if (n.start()) 
            do {
                os << n; 
            } while (n.next());
    }
    else {
#if IDA_SDK_VERSION >= 700
        funcset_t *pfuncs = find_idcfuncs();
        if (!pfuncs) {
            os << "--- could not find idcfuncs\n";
            return;
        }
        IDCFuncs = *pfuncs;
#endif
        os << "------------idcfuncs-----------\n";
        os << IDCFuncs;

        // note: there seems to be no official way of getting a list of
        // currently loaded idc functions.

        os << "------------compiled functions-----------\n";

        dump_idc_funcs(os);
    }
}
