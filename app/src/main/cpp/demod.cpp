// DeMod native engine: fast DEX parsing + normalized method fingerprints + diff,
// and printable-string diff for native libraries. All big data is mmap'ed.
#include <jni.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

typedef std::unordered_map<uint64_t, std::pair<uint16_t, uint32_t>> RefMap;

uint8_t LEN[256];
std::string NM[256];
std::once_flag g_init;

inline uint64_t fnv(const char* s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
    return h;
}
inline uint64_t fnv(const std::string& s) { return fnv(s.data(), s.size()); }

void initTables() {
    for (int i = 0; i < 256; i++) { LEN[i] = 1; char b[12]; snprintf(b, sizeof b, "op_%02x", i); NM[i] = b; }
    auto R = [](int a, int b, int l) { for (int i = a; i <= b; i++) LEN[i] = (uint8_t)l; };
    R(0x02, 0x02, 2); R(0x03, 0x03, 3); R(0x05, 0x05, 2); R(0x06, 0x06, 3); R(0x08, 0x08, 2); R(0x09, 0x09, 3);
    R(0x13, 0x13, 2); R(0x14, 0x14, 3); R(0x15, 0x16, 2); R(0x17, 0x17, 3); R(0x18, 0x18, 5); R(0x19, 0x19, 2);
    R(0x1a, 0x1a, 2); R(0x1b, 0x1b, 3); R(0x1c, 0x1c, 2); R(0x1f, 0x20, 2); R(0x22, 0x23, 2); R(0x24, 0x26, 3);
    R(0x29, 0x29, 2); R(0x2a, 0x2c, 3); R(0x2d, 0x3d, 2); R(0x44, 0x6d, 2); R(0x6e, 0x72, 3); R(0x74, 0x78, 3);
    R(0x90, 0xaf, 2); R(0xd0, 0xe2, 2); R(0xfa, 0xfb, 4); R(0xfc, 0xfd, 3); R(0xfe, 0xff, 2);

    static const char* base[] = {"nop", "move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16",
        "move-object", "move-object/from16", "move-object/16", "move-result", "move-result-wide", "move-result-object",
        "move-exception", "return-void", "return", "return-wide", "return-object", "const/4", "const/16", "const",
        "const/high16", "const-wide/16", "const-wide/32", "const-wide", "const-wide/high16", "const-string",
        "const-string/jumbo", "const-class", "monitor-enter", "monitor-exit", "check-cast", "instance-of", "array-length",
        "new-instance", "new-array", "filled-new-array", "filled-new-array/range", "fill-array-data", "throw", "goto",
        "goto/16", "goto/32", "packed-switch", "sparse-switch", "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double",
        "cmp-long", "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz",
        "if-lez"};
    for (int i = 0; i < 62; i++) NM[i] = base[i];
    static const char* suf[] = {"", "-wide", "-object", "-boolean", "-byte", "-char", "-short"};
    struct G { int s; const char* n; } gs[] = {{0x44, "aget"}, {0x4b, "aput"}, {0x52, "iget"}, {0x59, "iput"}, {0x60, "sget"}, {0x67, "sput"}};
    for (auto& g : gs) for (int k = 0; k < 7; k++) NM[g.s + k] = std::string(g.n) + suf[k];
    static const char* inv[] = {"virtual", "super", "direct", "static", "interface"};
    for (int k = 0; k < 5; k++) { NM[0x6e + k] = std::string("invoke-") + inv[k]; NM[0x74 + k] = std::string("invoke-") + inv[k] + "/range"; }
    static const char* un[] = {"neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double", "int-to-long",
        "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double", "float-to-int", "float-to-long",
        "float-to-double", "double-to-int", "double-to-long", "double-to-float", "int-to-byte", "int-to-char", "int-to-short"};
    for (int k = 0; k < 21; k++) NM[0x7b + k] = un[k];
    static const char* bo[] = {"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"};
    static const char* ty[] = {"int", "long", "float", "double"};
    int st[] = {0x90, 0x9b, 0xa6, 0xab}; int cnt[] = {11, 11, 5, 5};
    for (int t = 0; t < 4; t++) for (int k = 0; k < cnt[t]; k++) {
        std::string n = std::string(bo[k]) + "-" + ty[t];
        NM[st[t] + k] = n; NM[st[t] + 0x20 + k] = n + "/2addr";
    }
    static const char* l16[] = {"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16"};
    for (int k = 0; k < 8; k++) NM[0xd0 + k] = l16[k];
    for (int k = 0; k < 11; k++) NM[0xd8 + k] = std::string(k == 1 ? "rsub-int" : bo[k] + std::string("-int")) + (k == 1 ? "/lit8" : "/lit8");
    NM[0xfa] = "invoke-polymorphic"; NM[0xfb] = "invoke-polymorphic/range"; NM[0xfc] = "invoke-custom";
    NM[0xfd] = "invoke-custom/range"; NM[0xfe] = "const-method-handle"; NM[0xff] = "const-method-type";
}

std::string quote(const std::string& s) {
    std::string o = "\""; size_t n = 0;
    for (unsigned char c : s) {
        if (n >= 160) { if ((c & 0xC0) == 0x80) continue; o += "..."; break; }
        n++;
        if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
        else if (c == '\n') o += "\\n";
        else if (c == '\t') o += "\\t";
        else if (c == '\r') o += "\\r";
        else if (c < 0x20) o += ' ';
        else o += (char)c;
    }
    return o + "\"";
}

std::string clean(std::string s) {
    for (char& c : s) if (c == '\t' || c == '\n' || c == '\r' || c == '\x1e' || c == '\x1f') c = ' ';
    return s;
}

struct Dex {
    const uint8_t* b = nullptr; size_t sz = 0; bool ok = false;
    uint32_t strN = 0, typeN = 0, protoN = 0, fieldN = 0, methN = 0, classN = 0;
    uint32_t strO = 0, typeO = 0, protoO = 0, fieldO = 0, methO = 0, classO = 0;
    Dex() {}
    Dex(const Dex&) = delete;
    Dex& operator=(const Dex&) = delete;
    ~Dex() { if (b) munmap((void*)b, sz); }
    uint32_t u32(size_t o) const { uint32_t v = 0; if (o + 4 <= sz) memcpy(&v, b + o, 4); return v; }
    uint32_t u16(size_t o) const { uint16_t v = 0; if (o + 2 <= sz) memcpy(&v, b + o, 2); return v; }
    uint32_t uleb(size_t& o) const {
        uint32_t r = 0; int s = 0;
        while (o < sz) { uint8_t c = b[o++]; r |= (uint32_t)(c & 0x7f) << s; if (!(c & 0x80)) break; s += 7; if (s > 28) break; }
        return r;
    }
    bool open(const std::string& path) {
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size < 0x70) { close(fd); return false; }
        void* m = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (m == MAP_FAILED) return false;
        b = (const uint8_t*)m; sz = (size_t)st.st_size;
        if (memcmp(b, "dex\n", 4) != 0) { munmap(m, sz); b = nullptr; return false; }
        strN = u32(56); strO = u32(60); typeN = u32(64); typeO = u32(68); protoN = u32(72); protoO = u32(76);
        fieldN = u32(80); fieldO = u32(84); methN = u32(88); methO = u32(92); classN = u32(96); classO = u32(100);
        ok = true; return true;
    }
    std::string str(uint32_t i) const {
        if (i >= strN) return "?";
        size_t o = u32(strO + 4ull * i);
        if (o >= sz) return "?";
        uleb(o);
        size_t e = o; while (e < sz && b[e]) e++;
        return std::string((const char*)b + o, e - o);
    }
    std::string type(uint32_t i) const { return i >= typeN ? "?" : str(u32(typeO + 4ull * i)); }
    std::string proto(uint32_t i) const {
        if (i >= protoN) return "()?";
        size_t p = protoO + 12ull * i; uint32_t ret = u32(p + 4), po = u32(p + 8);
        std::string s = "(";
        if (po) { uint32_t n = u32(po); if (n < 256) for (uint32_t k = 0; k < n; k++) s += type(u16(po + 4 + 2ull * k)); }
        return s + ")" + type(ret);
    }
    std::string field(uint32_t i) const {
        if (i >= fieldN) return "?";
        size_t p = fieldO + 8ull * i;
        return type(u16(p)) + "->" + str(u32(p + 4)) + ":" + type(u16(p + 2));
    }
    std::string method(uint32_t i) const {
        if (i >= methN) return "?";
        size_t p = methO + 8ull * i;
        return type(u16(p)) + "->" + str(u32(p + 4)) + proto(u16(p + 2));
    }
};

// Produces pseudo-smali lines (registers omitted -> resilient to register renaming).
// Lines are joined with 0x1f. keyOnly keeps just invoke / const-string / new-instance.
void disasm(const Dex& d, uint32_t off, std::string* out, uint64_t* hash, RefMap* cs, uint16_t di, int maxLines, bool keyOnly) {
    uint64_t h = 1469598103934665603ULL;
    if ((size_t)off + 16 > d.sz) { if (hash) *hash = h; return; }
    uint32_t n = d.u32(off + 12);
    size_t base = (size_t)off + 16;
    if (base + (size_t)n * 2 > d.sz) n = (uint32_t)((d.sz - base) / 2);
    auto U = [&](uint32_t i) -> uint32_t { return i < n ? d.u16(base + (size_t)i * 2) : 0u; };
    int lines = 0; uint32_t i = 0; std::string t;
    while (i < n) {
        uint32_t u = U(i); uint8_t op = u & 0xff; uint32_t len = 1; t.clear();
        if (op == 0 && u != 0) {
            if (u == 0x100) len = U(i + 1) * 2 + 4;
            else if (u == 0x200) len = U(i + 1) * 4 + 2;
            else if (u == 0x300) len = (U(i + 1) * (U(i + 2) | (U(i + 3) << 16)) + 1) / 2 + 4;
            t = "payload";
        } else {
            len = LEN[op]; t = NM[op];
            switch (op) {
                case 0x12: t += " " + std::to_string((int)((int16_t)u >> 12)); break;
                case 0x13: case 0x16: t += " " + std::to_string((int)(int16_t)U(i + 1)); break;
                case 0x14: case 0x17: t += " " + std::to_string((int32_t)(U(i + 1) | (U(i + 2) << 16))); break;
                case 0x15: t += " " + std::to_string((int32_t)(U(i + 1) << 16)); break;
                case 0x18: { uint64_t v = 0; for (int k = 4; k >= 1; k--) v = (v << 16) | U(i + k); t += " " + std::to_string((int64_t)v); break; }
                case 0x19: t += " " + std::to_string((int64_t)((uint64_t)U(i + 1) << 48)); break;
                case 0x1a: case 0x1b: {
                    uint32_t x = op == 0x1a ? U(i + 1) : (U(i + 1) | (U(i + 2) << 16));
                    std::string s = d.str(x);
                    if (cs) cs->emplace(fnv(s), std::make_pair(di, x));
                    t += " " + quote(s); break;
                }
                case 0x1c: case 0x1f: case 0x20: case 0x22: case 0x23: case 0x24: case 0x25: t += " " + d.type(U(i + 1)); break;
                case 0xfa: case 0xfb: t += " " + d.method(U(i + 1)); break;
                default:
                    if (op >= 0x52 && op <= 0x6d) t += " " + d.field(U(i + 1));
                    else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) t += " " + d.method(U(i + 1));
            }
        }
        if (len == 0) len = 1;
        for (unsigned char c : t) { h ^= c; h *= 1099511628211ULL; }
        h ^= 10; h *= 1099511628211ULL;
        if (out) {
            bool keep = !keyOnly || op == 0x1a || op == 0x1b || op == 0x22 || (op >= 0x6e && op <= 0x78 && op != 0x73);
            if (keep) {
                if (lines < maxLines) { *out += clean(t); *out += '\x1f'; }
                else if (lines == maxLines) *out += "...(truncated)\x1f";
                lines++;
            }
        }
        i += len;
    }
    if (hash) *hash = h;
}

struct MRec { uint16_t dex; uint32_t midx; uint32_t code; uint64_t h; };

struct Model {
    std::vector<std::unique_ptr<Dex>> dx;
    std::unordered_map<uint64_t, MRec> m;
    std::unordered_map<uint64_t, std::pair<uint16_t, uint32_t>> cls;
    RefMap cs;
    void load(const std::vector<std::string>& paths) {
        for (auto& p : paths) { std::unique_ptr<Dex> d(new Dex()); d->open(p); dx.push_back(std::move(d)); }
        for (uint16_t di = 0; di < dx.size(); di++) {
            const Dex& d = *dx[di];
            if (!d.ok) continue;
            for (uint32_t c = 0; c < d.classN; c++) {
                size_t cd = d.classO + 32ull * c;
                uint32_t ci = d.u32(cd), data = d.u32(cd + 24);
                cls[fnv(d.type(ci))] = std::make_pair(di, ci);
                if (!data) continue;
                size_t o = data;
                uint32_t sf = d.uleb(o); uint32_t inf = d.uleb(o); uint32_t dm = d.uleb(o); uint32_t vm = d.uleb(o);
                for (uint32_t k = 0; k < sf + inf; k++) { d.uleb(o); d.uleb(o); }
                for (int pass = 0; pass < 2; pass++) {
                    uint32_t n = pass ? vm : dm, idx = 0;
                    for (uint32_t k = 0; k < n; k++) {
                        idx += d.uleb(o); d.uleb(o); uint32_t code = d.uleb(o);
                        MRec r{di, idx, code, 0};
                        if (code) { uint64_t h = 0; disasm(d, code, nullptr, &h, &cs, di, 0, false); r.h = h; }
                        m.emplace(fnv(d.method(idx)), r);
                    }
                }
            }
        }
    }
    std::string name(const MRec& r) const { return clean(dx[r.dex]->method(r.midx)); }
    std::string body(const MRec& r, int maxL, bool keyOnly) const {
        std::string t;
        if (!r.code) return "(abstract/native)";
        uint64_t h; disasm(*dx[r.dex], r.code, &t, &h, nullptr, r.dex, maxL, keyOnly);
        return t;
    }
};

std::vector<std::string> toVec(JNIEnv* env, jobjectArray arr) {
    std::vector<std::string> v;
    jsize n = env->GetArrayLength(arr);
    for (jsize i = 0; i < n; i++) {
        jstring s = (jstring)env->GetObjectArrayElement(arr, i);
        const char* c = env->GetStringUTFChars(s, nullptr);
        v.emplace_back(c ? c : "");
        env->ReleaseStringUTFChars(s, c);
        env->DeleteLocalRef(s);
    }
    return v;
}
std::string toStr(JNIEnv* env, jstring s) {
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string r(c ? c : "");
    env->ReleaseStringUTFChars(s, c);
    return r;
}

// Report format (tab separated, bodies joined by 0x1f, before/after by 0x1e is not used: separate columns):
// CA type | CD type | MC key dex before after | MA key dex body | MD key dex | SA str | SD str | CNT ...
int doDiff(const std::vector<std::string>& A, const std::vector<std::string>& B, const std::string& outp) {
    std::call_once(g_init, initTables);
    Model a, b;
    std::thread t([&] { a.load(A); });
    b.load(B);
    t.join();
    FILE* f = fopen(outp.c_str(), "w");
    if (!f) return -1;
    long ca = 0, cd = 0, mc = 0, ma = 0, md = 0, sa = 0, sd = 0;
    for (auto& kv : b.cls) if (!a.cls.count(kv.first)) {
        if (++ca <= 200000) fprintf(f, "CA\t%s\n", clean(b.dx[kv.second.first]->type(kv.second.second)).c_str());
    }
    for (auto& kv : a.cls) if (!b.cls.count(kv.first)) {
        if (++cd <= 200000) fprintf(f, "CD\t%s\n", clean(a.dx[kv.second.first]->type(kv.second.second)).c_str());
    }
    for (auto& kv : b.m) {
        auto it = a.m.find(kv.first);
        if (it == a.m.end() || it->second.h == kv.second.h) continue;
        if (++mc <= 6000)
            fprintf(f, "MC\t%s\t%u\t%s\t%s\n", b.name(kv.second).c_str(), (unsigned)kv.second.dex,
                    a.body(it->second, 300, false).c_str(), b.body(kv.second, 300, false).c_str());
    }
    for (auto& kv : b.m) if (!a.m.count(kv.first)) {
        if (++ma <= 150000) fprintf(f, "MA\t%s\t%u\t%s\n", b.name(kv.second).c_str(), (unsigned)kv.second.dex, b.body(kv.second, 120, true).c_str());
    }
    for (auto& kv : a.m) if (!b.m.count(kv.first)) {
        if (++md <= 60000) fprintf(f, "MD\t%s\t%u\n", a.name(kv.second).c_str(), (unsigned)kv.second.dex);
    }
    for (auto& kv : b.cs) if (!a.cs.count(kv.first)) {
        if (++sa <= 100000) fprintf(f, "SA\t%s\n", clean(quote(b.dx[kv.second.first]->str(kv.second.second))).c_str());
    }
    for (auto& kv : a.cs) if (!b.cs.count(kv.first)) {
        if (++sd <= 100000) fprintf(f, "SD\t%s\n", clean(quote(a.dx[kv.second.first]->str(kv.second.second))).c_str());
    }
    fprintf(f, "CNT\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n", ca, cd, ma, md, mc, sa, sd);
    fclose(f);
    return (int)(ca + cd + ma + md + mc + sa + sd > 0x7fffffff ? 0x7fffffff : ca + cd + ma + md + mc + sa + sd);
}

void scanStrings(const std::string& p, int minLen, std::unordered_map<uint64_t, std::string>& mp) {
    if (p.empty()) return;
    int fd = ::open(p.c_str(), O_RDONLY);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return; }
    void* m = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return;
    const uint8_t* b = (const uint8_t*)m; size_t n = (size_t)st.st_size, s = 0;
    for (size_t i = 0; i <= n; i++) {
        bool pr = i < n && b[i] >= 0x20 && b[i] < 0x7f;
        if (pr) { continue; }
        size_t len = i - s;
        if (len >= (size_t)minLen && len <= 300 && mp.size() < 400000) mp.emplace(fnv((const char*)b + s, len), std::string((const char*)b + s, len));
        s = i + 1;
    }
    munmap(m, n);
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL Java_com_tenix_demod_NativeBridge_diffDex(JNIEnv* env, jclass, jobjectArray ja, jobjectArray jb, jstring jout) {
    try {
        std::vector<std::string> a = toVec(env, ja), b = toVec(env, jb);
        return doDiff(a, b, toStr(env, jout));
    } catch (...) { return -2; }
}

extern "C" JNIEXPORT jint JNICALL Java_com_tenix_demod_NativeBridge_diffStrings(JNIEnv* env, jclass, jstring ja, jstring jb, jstring jout, jint minLen) {
    try {
        std::unordered_map<uint64_t, std::string> a, b;
        scanStrings(toStr(env, ja), minLen, a);
        scanStrings(toStr(env, jb), minLen, b);
        FILE* f = fopen(toStr(env, jout).c_str(), "w");
        if (!f) return -1;
        int n = 0, cap = 4000;
        for (auto& kv : b) if (!a.count(kv.first) && n < cap) { fprintf(f, "A\t%s\n", clean(kv.second).c_str()); n++; }
        int m = 0;
        for (auto& kv : a) if (!b.count(kv.first) && m < cap) { fprintf(f, "D\t%s\n", clean(kv.second).c_str()); m++; }
        fclose(f);
        return n + m;
    } catch (...) { return -2; }
}

extern "C" JNIEXPORT jstring JNICALL Java_com_tenix_demod_NativeBridge_version(JNIEnv* env, jclass) {
    return env->NewStringUTF("DeMod native engine 1.0 (C++17)");
}
