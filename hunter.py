'''
MISC HUNTER 入口

用法:
    python hunter.py <文件1> [文件2 ...]

流程:
    1. 命令行接收目标文件
    2. 递归分析队列: 每轮产出的新文件自动重新进队列
    3. 每轮 findings 打印到终端
    4. 全部结束后写 output/report.txt

示例:
    python hunter.py samples/snake.jpg
'''

import os
import sys
from datetime import datetime

from core.engine import Engine
from core.plugin_loader import discover_plugins
from utils.decoders import xor_decrypt, looks_like_text
from utils.paths import OUTPUT_DIR, EXTRACT_DIR, ensure_dirs

# 插件自动发现: 扫描 plugins/ 目录, 按 priority 排序
# 新插件只需在 plugins/ 下新建文件继承 Plugin, 无需改这里
PLUGINS = discover_plugins()

# 终端输出统一 UTF-8 (Windows 控制台默认 GBK 会乱码)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SEVERITY_MARK = {"INFO": "[+]", "WARNING": "[!]", "ERROR": "[x]"}


def print_findings(context):
    """终端呈现一轮分析的所有 findings(含找到的具体内容)"""
    for f in context.findings:
        mark = SEVERITY_MARK.get(f["severity"], "[?]")
        print(f"  {mark} {f['message']}")
        data = f.get("data") or {}

        # 各种 finding 的详细内容, 直接展示在终端
        if f["code"] == "FLAG_FOUND":
            print(f"     >>> FLAG: {data['flag']}")
        elif f["code"] == "DECODED":
            for i, layer in enumerate(data.get("layers", [])):
                text = layer["result"].strip()
                if len(text) > 200:
                    text = text[:200] + "..."
                print(f"     解码第{i+1}层 [{layer['decoder']}]: {text}")
        elif f["code"] == "STRINGS_EXTRACTED":
            for s in data.get("preview", []):
                print(f"     | {s}")
            if data.get("count", 0) > len(data.get("preview", [])):
                print(f"     | ... 共{data['count']}条, 完整内容见文件")


def _ask_for_key(target, context, analyzed, targets):
    """
    人机接力: 询问用户是否有密钥, 有则尝试 XOR 解密
    解密产物重新进队列继续分析(递归)
    1.0 只支持 XOR; Serpent/AES 等留密钥解密框架(3.0)
    """
    try:
        key = input(f"  [?] 疑似加密数据: {os.path.basename(target)}\n"
                    "      如有密钥请输入(直接回车跳过): ").strip()
    except EOFError:
        return
    if not key:
        return

    with open(target, "rb") as f:
        data = f.read()
    decrypted = xor_decrypt(data, key.encode())

    if decrypted is None or not looks_like_text(decrypted, letter_th=0.75):
        print("  [x] 解密结果不可读: 密钥可能不对, 或该数据不是 XOR 加密")
        return

    # 解密成功: 明文落盘, 进队列继续分析
    ensure_dirs()
    out_path = os.path.join(
        str(EXTRACT_DIR),
        os.path.basename(target) + ".decrypted.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(decrypted.decode("utf-8", errors="replace"))

    context.extracted_files.append({
        "path": out_path,
        "source": target,
        "method": "MANUAL_KEY_XOR",
        "offset": 0
    })
    print(f"  [+] 密钥有效! 解密结果已写入: {out_path}")
    if out_path not in analyzed:
        targets.append(out_path)


def run_analysis(targets):
    """递归分析队列, 返回所有轮次的 context 列表(供报告使用)"""
    analyzed = set()
    contexts = []

    while targets:
        target = targets.pop()
        if target in analyzed:
            continue
        analyzed.add(target)

        print(f"\n[分析] {target}")
        context = Engine(target, PLUGINS).run()
        contexts.append(context)
        print_findings(context)

        # ===== 人机接力: 插件发现疑似加密但破解失败, 询问用户密钥 =====
        needed = [f for f in context.findings if f["code"] == "DECRYPT_NEEDED"]
        if needed and sys.stdin.isatty():   # 仅交互终端询问(管道/自动化不卡死)
            _ask_for_key(target, context, analyzed, targets)

        for file in context.extracted_files:
            path = file["path"]
            if path not in analyzed:
                print(f"  [+] 提取新文件: {path}")
                targets.append(path)

    return contexts


def write_report(contexts):
    """把每轮分析的 findings/extracted 汇总成 output/report.txt"""
    ensure_dirs()
    lines = []
    lines.append("=" * 44)
    lines.append("MISC HUNTER REPORT")
    lines.append("=" * 44)
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    all_flags = []
    # 待人工分析清单: (目标, 原因)
    manual = []

    for ctx in contexts:
        lines.append("-" * 44)
        lines.append(f"目标: {ctx.target}")

        # 文件类型: 从 FileTypeDetector 的 finding 里找
        ftype = "未知"
        for f in ctx.findings:
            if f["code"] == "FILE_TYPE_DETECTED":
                ftype = f["data"].get("type", "未知")
        lines.append(f"文件类型: {ftype}")
        lines.append("")

        lines.append("Findings:")
        codes = []
        for f in ctx.findings:
            mark = SEVERITY_MARK.get(f["severity"], "[?]")
            lines.append(f"  {mark} [{f['code']}] {f['message']}")
            codes.append(f["code"])
            if f["code"] == "FLAG_FOUND":
                all_flags.append(f["data"]["flag"])
        lines.append("")

        if ctx.extracted_files:
            lines.append("Extracted:")
            for e in ctx.extracted_files:
                lines.append(f"  - {e['path']}")
            lines.append("")

        # 判定是否"待人工分析": 工具没搞定的要明确告诉人, 不能悄悄消失
        # 有 STRINGS_EXTRACTED 说明内容已提取呈现(有结论), 不算待人工
        has_extract = bool(ctx.extracted_files)
        has_flag = "FLAG_FOUND" in codes
        has_content = "STRINGS_EXTRACTED" in codes
        if "DECRYPT_NEEDED" in codes:
            manual.append((ctx.target, "疑似加密数据, 自动破解失败, 可提供密钥重试"))
        elif (("FILE_TYPE_UNKNOWN" in codes) and not has_extract
                and not has_flag and not has_content):
            manual.append((ctx.target, "未知文件类型, 无任何提取结果"))

    lines.append("=" * 44)
    lines.append("待人工分析")
    lines.append("=" * 44)
    if manual:
        for t, reason in manual:
            lines.append(f"  - {t}")
            lines.append(f"      原因: {reason}")
    else:
        lines.append("  无(所有文件均已自动处理或有明确结论)")
    lines.append("")

    lines.append("=" * 44)
    lines.append("FLAG 汇总")
    lines.append("=" * 44)
    if all_flags:
        for flag in all_flags:
            lines.append(f"  flag: {flag}")
    else:
        lines.append("  未发现 flag")
    lines.append("")
    lines.append("=" * 44)

    report_path = OUTPUT_DIR / "report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return report_path


def print_summary(contexts):
    """终端最终摘要: 每个文件的关键结论(人话版, 不刷屏)
    详细流水见上方逐轮输出与 output/report.txt"""
    bar = "=" * 52
    print(f"\n{bar}")
    print("  分析完成 · 简要汇总")
    print(bar)

    all_flags = []
    manual = []

    for ctx in contexts:
        rel = os.path.relpath(ctx.target)

        ftype = "未知"
        for f in ctx.findings:
            if f["code"] == "FILE_TYPE_DETECTED":
                ftype = f["data"].get("type", "未知")

        # 收集该文件的关键结论(按出现顺序)
        lines_out = []
        for f in ctx.findings:
            d = f.get("data") or {}
            if f["code"] == "FLAG_FOUND":
                all_flags.append(d["flag"])
                lines_out.append(f"[+] FLAG: {d['flag']}")
            elif f["code"] == "DECODED":
                final = d["layers"][-1]["result"].strip()
                lines_out.append(f"[+] 解码({len(d['layers'])}层): {final[:110]}")
            elif f["code"] == "CAESAR_DECODED":
                lines_out.append(f"[+] {f['message'][:120]}")
            elif f["code"] == "KEYWORD_FOUND":
                lines_out.append(f"[!] 关键字: {', '.join(d.get('keywords', []))}")
            elif f["code"] == "STRINGS_EXTRACTED" and ftype == "未知" and d.get("preview"):
                # 只显示文本类文件的字符串内容(二进制里的噪音字符串无意义)
                lines_out.append(f"[+] 字符串: {d['preview'][0][:110]}")
            elif f["code"] == "DECRYPT_NEEDED":
                manual.append(rel)
                lines_out.append("[!] 疑似加密数据 — 需密钥/人工")

        # 提取产物(去重)
        if ctx.extracted_files:
            names = sorted({os.path.basename(e["path"]) for e in ctx.extracted_files})
            lines_out.append(f"[+] 提取 {len(names)} 个: {', '.join(names)}")

        if not lines_out:
            continue  # 纯噪音轮(全是 NOT_FOUND), 不显示

        print(f"\n  {rel}  [{ftype}]")
        for l in lines_out:
            print(f"    {l}")

    print(f"\n{bar}")
    if all_flags:
        uniq = list(dict.fromkeys(all_flags))
        print(f"  FLAG 汇总: {', '.join(uniq)}")
    else:
        print("  FLAG: 未发现")
    if manual:
        names = ", ".join(os.path.basename(m) for m in dict.fromkeys(manual))
        print(f"  待人工分析: {names}(需密钥/进一步分析)")
    print(bar)


def main():
    targets = sys.argv[1:]
    if not targets:
        print("用法: python hunter.py <文件1> [文件2 ...]")
        print("示例: python hunter.py samples/snake.jpg")
        return

    ensure_dirs()
    contexts = run_analysis(targets)
    report_path = write_report(contexts)
    print_summary(contexts)
    print(f"\n[完成] 详细报告: {report_path}")


if __name__ == "__main__":
    main()
