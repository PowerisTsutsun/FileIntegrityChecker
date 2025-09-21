// main.cpp — zero-dependency SHA-256 file integrity tool
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <filesystem>
#include <cstdint>
#include <cctype>

using namespace std;

// ---------- tiny SHA-256 (public-domain style) ----------
struct TinySHA256 {
    uint32_t s[8]; uint64_t bitlen; uint8_t buf[64]; size_t blen;
    static inline uint32_t R(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
    static inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}
    static inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}
    static inline uint32_t BS0(uint32_t x){return R(x,2)^R(x,13)^R(x,22);}
    static inline uint32_t BS1(uint32_t x){return R(x,6)^R(x,11)^R(x,25);}
    static inline uint32_t SS0(uint32_t x){return R(x,7)^R(x,18)^(x>>3);}
    static inline uint32_t SS1(uint32_t x){return R(x,17)^R(x,19)^(x>>10);}
    static constexpr uint32_t K[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    void init(){ blen=0; bitlen=0;
      s[0]=0x6a09e667; s[1]=0xbb67ae85; s[2]=0x3c6ef372; s[3]=0xa54ff53a;
      s[4]=0x510e527f; s[5]=0x9b05688c; s[6]=0x1f83d9ab; s[7]=0x5be0cd19; }
    void transform(const uint8_t b[64]){
      uint32_t w[64];
      for(int i=0;i<16;i++)
        w[i]=(uint32_t(b[i*4])<<24)|(uint32_t(b[i*4+1])<<16)|
             (uint32_t(b[i*4+2])<<8)|(uint32_t(b[i*4+3]));
      for(int i=16;i<64;i++) w[i]=SS1(w[i-2])+w[i-7]+SS0(w[i-15])+w[i-16];
      uint32_t a=s[0],b0=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
      for(int i=0;i<64;i++){ uint32_t t1=h+BS1(e)+Ch(e,f,g)+K[i]+w[i];
        uint32_t t2=BS0(a)+Maj(a,b0,c); h=g; g=f; f=e; e=d+t1; d=c; c=b0; b0=a; a=t1+t2; }
      s[0]+=a; s[1]+=b0; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
    }
    void update(const void* data,size_t len){
      const uint8_t* p=(const uint8_t*)data;
      for(size_t i=0;i<len;i++){
        buf[blen++]=p[i];
        if(blen==64){ transform(buf); bitlen+=512; blen=0; }
      }
    }
    void final(uint8_t out[32]){
      bitlen += blen*8ULL;
      buf[blen++]=0x80;
      if(blen>56){ while(blen<64) buf[blen++]=0; transform(buf); blen=0; }
      while(blen<56) buf[blen++]=0;
      for(int i=7;i>=0;i--) buf[blen++]=uint8_t((bitlen>>(i*8))&0xFF);
      transform(buf);
      for(int i=0;i<8;i++){
        out[i*4]  = uint8_t((s[i]>>24)&0xFF);
        out[i*4+1]= uint8_t((s[i]>>16)&0xFF);
        out[i*4+2]= uint8_t((s[i]>>8)&0xFF);
        out[i*4+3]= uint8_t(s[i]&0xFF);
      }
    }
};
static string sha256_stream(istream& in){
    TinySHA256 ctx; ctx.init();
    vector<uint8_t> buf(1<<16);
    while(in){
        in.read((char*)buf.data(), buf.size());
        streamsize n=in.gcount();
        if(n>0) ctx.update(buf.data(), size_t(n));
    }
    uint8_t out[32]; ctx.final(out);
    static const char* hex="0123456789abcdef";
    string s; s.resize(64);
    for(int i=0;i<32;i++){ s[2*i]=hex[out[i]>>4]; s[2*i+1]=hex[out[i]&0xF]; }
    return s;
}
// ---------- end tiny SHA-256 ----------

static string sha256_file_or_stdin(const filesystem::path& p){
    if(p == "-"){ ios::sync_with_stdio(false); cin.tie(nullptr); return sha256_stream(cin); }
    ifstream f(p, ios::binary);
    if(!f) throw runtime_error("open failed: " + p.string());
    return sha256_stream(f);
}
static inline void trim_cr(string& s){ if(!s.empty() && s.back()=='\r') s.pop_back(); }
static inline bool is_hex64(const string& s){
    if(s.size()!=64) return false;
    for(char c: s){ if(!isxdigit((unsigned char)c)) return false; }
    return true;
}
static void record_hash(const filesystem::path& p){
    string h=sha256_file_or_stdin(p);
    if(p=="-"){ cout<<h<<"  -\n"; return; }
    ofstream o(p.string()+".sha256");
    if(!o) throw runtime_error("cannot write .sha256");
    o<<h<<"  "<<p.filename().string()<<"\n";
    cout<<"wrote: "<<p.filename().string()<<".sha256\n";
}
static bool verify_file(const filesystem::path& p){
    ifstream ref(p.string()+".sha256");
    if(!ref) throw runtime_error("missing sidecar .sha256");
    string line; if(!getline(ref,line)) throw runtime_error("cannot read .sha256");
    trim_cr(line);
    size_t pos=line.find_first_of(" \t");
    if(pos==string::npos) throw runtime_error("invalid .sha256 format");
    string expected=line.substr(0,pos);
    for(char& c: expected) c = (char)tolower((unsigned char)c);
    if(!is_hex64(expected)) throw runtime_error("invalid hash (need 64 hex chars)");
    string actual=sha256_file_or_stdin(p);
    bool ok=(actual==expected);
    cout<<(ok?"OK  ":"MISMATCH  ")<<p<<"\n";
    if(!ok){ cerr<<"expected: "<<expected<<"\nactual:   "<<actual<<"\n"; }
    return ok;
}

int main(int argc, char** argv){
    if(argc<3){ cerr<<"usage: "<<argv[0]<<" <hash|record|verify> <path|->\n"; return 1; }
    string cmd=argv[1]; filesystem::path p=argv[2];
    try{
        if(cmd=="hash"){ cout<<sha256_file_or_stdin(p)<<"  "<<(p=="-"?string("-"):p.filename().string())<<"\n"; }
        else if(cmd=="record"){ record_hash(p); }
        else if(cmd=="verify"){ return verify_file(p)?0:2; }
        else { cerr<<"unknown cmd\n"; return 1; }
    }catch(const exception& e){ cerr<<"error: "<<e.what()<<"\n"; return 1; }
}
