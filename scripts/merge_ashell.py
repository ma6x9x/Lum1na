#!/usr/bin/env python3
# merge_ashell.py -- embed the a-Shell mini ios_system runtime into a built .app.
# Adapted from the filza27.2 prepare_dev_terminal.sh merge (lab-internal script;
# mechanism credit: the FilzaSlop/worse_query toolchain; a-Shell is MIT, holzschu).
#
# Usage: merge_ashell.py <path/to/App.app> [a-shell-mini.ipa]
# Env:   ASHELL_IPA overrides argv[2]. Missing payload = clean skip (the app
#        still builds; the terminal pane reports "not embedded").

import os, re, shutil, sys, zipfile

TEX_NAMES = ('xetex','luatex','luahbtex','pdftex','euptex','texlua53','texluajit',
             'kpathsea','kpsewhich','bibtex','metapost','mflua','mplib','mf')

def main():
    app = sys.argv[1]
    ipa = os.environ.get('ASHELL_IPA', sys.argv[2] if len(sys.argv) > 2 else '')
    if not app or not os.path.isdir(app):
        sys.exit('app not found')
    if not ipa or not os.path.isfile(ipa):
        print('[merge_ashell] no a-Shell mini IPA provided - SKIPPING (soft)')
        print('[merge_ashell] set ASHELL_IPA (env/secret) to embed a full terminal')
        return

    z = zipfile.ZipFile(ipa)
    names = z.namelist()
    prefix = None
    for n in names:
        m = re.match(r'(Payload/[^/]+\.app/)', n)
        if m:
            prefix = m.group(1)
            break
    if not prefix:
        sys.exit('cannot find an app prefix in the a-Shell IPA')
    print('[merge_ashell] a-Shell app prefix:', prefix)

    def excluded(name):
        low = name.lower().replace('.framework', '')
        if low.startswith('python') or low in ('node','npm','node-fetch','vim','xxd'):
            return True
        if low in TEX_NAMES or low.startswith('lua') or (low.startswith('tex') and low != 'text'):
            return True
        if low in ('libllvm','clang','lld','ar'):
            return True
        return False

    fw_dst = os.path.join(app, 'Frameworks')
    os.makedirs(fw_dst, exist_ok=True)

    # libssh embeds unconditionally (independent of the a-Shell payload):
    # the main target links -lssh.4 and Vendor/libssh carries the dylib.
    libssh = os.environ.get('LIBSSH_DYLIB', '')
    if not libssh:
        for cand in ('Vendor/libssh/libssh.4.dylib',
                     os.path.join(os.path.dirname(os.path.abspath(app)), '..', 'Vendor', 'libssh', 'libssh.4.dylib')):
            if os.path.isfile(cand):
                libssh = os.path.abspath(cand)
                break
    if libssh and os.path.isfile(libssh):
        dst = os.path.join(fw_dst, 'libssh.4.dylib')
        shutil.copyfile(libssh_env, dst)
        os.chmod(dst, 0o755)
        print('[merge_ashell] libssh.4.dylib embedded into Frameworks')
    else:
        print('[merge_ashell] WARNING: libssh.4.dylib not found - SSH pane will not load')

    copied = 0
    for n in names:
        rel = n[len(prefix):] if n.startswith(prefix) else None
        if not rel or rel.endswith('/'):
            continue
        top = rel.split('/')[0].lower().replace('.framework','')
        if excluded(top):
            continue
        dst = os.path.join(app, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with z.open(n) as s, open(dst,'wb') as d:
            shutil.copyfileobj(s,d)
        copied += 1
    print('[merge_ashell] copied', copied, 'files into the app')

    iosfw = os.path.join(fw_dst,'ios_system.framework','ios_system')
    if os.path.isfile(iosfw):
        os.chmod(iosfw, 0o755)
        sigdir = os.path.join(fw_dst,'ios_system.framework','_CodeSignature')
        if os.path.isdir(sigdir):
            shutil.rmtree(sigdir)
        print('[merge_ashell] ios_system.framework embedded')
    else:
        print('[merge_ashell] WARNING: ios_system.framework not found in the IPA')

main()
