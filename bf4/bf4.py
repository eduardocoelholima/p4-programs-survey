# very basic script to compile p4 files, measure elapsed time, print to terminal and save to a json file

import argparse
import subprocess
import sys
import os
import time
import json

compiler = 'ls'
directory = '.'
files = os.listdir(directory)
results = {}
results_file = "out.json"

for file in files:
    results[file] = {}
    start = time.time()
    subprocess.check_call([compiler, file], stdout=subprocess.DEVNULL)
    end = time.time()
    results[file]['elapsed-ms'] = (end - start) * 1000

json_out = json.dumps(results, indent = 3)
print(json_out)

with open(results_file, "w") as outfile:
    json.dump(results, outfile)

# to read a json dump:
with open(results_file, "r") as f:
    json_in = json.load(f)
print(json_in)


# if len(sys.argv) < 2:
#     print('usage: python3 {} <out dir>'.format(sys.argv[0]))
#     sys.exit(-1)
# fin = sys.stdin
# outdir = sys.argv[1]
# 
# def version(prog):
#     try:
#         subprocess.check_call(['p4test', '--parse-only', prog], stderr=DEVNULL, stdout=DEVNULL)
#         return 16
#     except:
#         try:
#             subprocess.check_call(['p4test', '--parse-only', '--std', 'p4-14', prog], stderr=DEVNULL, stdout=DEVNULL)
#             return 14
#         except:
#             return 0

# def add_suffix(file, suf):
#     bnm = os.path.basename(file)
#     exs = os.path.splitext(bnm)
#     return exs[0] + '-' + suf + exs[1]

# def add_suffix_and_join(file, suf, outdir):
#     return os.path.join(outdir, add_suffix(file, suf))

# parser = argparse.ArgumentParser(description='Benchmark p4 programs')

# parser.add_argument('-o', default='.', help='output directory')
# parser.add_argument('p4file', help='input p4 program')
# parser.add_argument('--std', choices=['p4-16', 'p4-14'])
# parser.add_argument('--psa', action='store_true', help='set if converting to psa, otherwise v1 with field lists')
# parser.add_argument('--validate', action='store_true', help='set if you don\'t want to validate output')

# parser.add_argument('--integration-file', default='./v1_integration.p4',
#     help='select integration file')

# parser.add_argument('--cleanup-only', action='store_true',
#     help='only clean up phase')

# parser.add_argument(
#     '--bf4-exec', help='location of bf4 exec (default:p4c-analysis)', default='p4c-analysis')

# parser.add_argument(
#     '--p4c-bm2-ss-exec', help='location of p4c-bm2-ss exec (default:p4c-bm2-ss)', default='p4c-bm2-ss')

# args = parser.parse_args()





# arglist=[args.p4c_bm2_ss_exec]
# crt_std = 'p4-16'
# if args.std is not None:
#     crt_std = args.std
# else:
#     vr = version(args.p4file)
#     if vr == 14:
#         crt_std = 'p4-14'
#     elif vr == 16:
#         crt_std = 'p4-16'
#     else:
#         print('problems parsing {}'.format(args.p4file))
#         sys.exit(1)
# arglist.extend(['--std', crt_std])

# outdir = args.o
# cleanout = add_suffix_and_join(args.p4file, 'clean', outdir)
# if args.psa:
#     arglist.extend(['--v1-psa', cleanout])
# else:
#     arglist.extend(['--make-field-lists', cleanout])

# arglist.append(args.p4file)
# subprocess.check_call(arglist)
# print('cleaned up {} -> {}. Validating...'.format(args.p4file, cleanout))
# if args.validate:
#     arglist=['p4test', '--validate', args.o]
#     subprocess.check_call(arglist)

# if not args.cleanup_only:
#     int_file = args.integration_file
#     '''
# trimmed=`basename $fname .p4`
# time p4c-analysis --dump-instrumented "${outdir}/${trimmed}-instrumented.p4" ${fname}
# echo "instrumented ${outdir}/${trimmed}-instrumented.p4"
# time p4c-analysis --expand-to "${outdir}/${trimmed}-instrumented-expanded.p4" "${outdir}/${trimmed}-instrumented.p4"
# echo "expanded ${outdir}/${trimmed}-instrumented-expanded.p4"
# time p4c-analysis --render-integration "${outdir}/${trimmed}-integrated.p4" \
#  --integration-template ${template} --render-only "${outdir}/${trimmed}-instrumented-expanded.p4"
# echo "integrated ${outdir}/${trimmed}-integrated.p4"
#     '''
#     outinstr = add_suffix_and_join(args.p4file, 'instrumented', outdir)

#     start = time.time()
#     subprocess.check_call([args.bf4_exec, '--dump-instrumented', outinstr, cleanout],
#         stderr=DEVNULL, stdout=DEVNULL)
#     end = time.time()
#     print('done instrumentation in {}ms'.format(int((end - start) * 1000)))
#     start = time.time()
#     outexpd = add_suffix_and_join(args.p4file, 'instrumented-expanded', outdir)
#     subprocess.check_call([args.bf4_exec, '--expand-to', outexpd, outinstr],
#         stderr=DEVNULL, stdout=DEVNULL)
#     end = time.time()
#     print('done primitive expansion in {}ms'.format(int((end - start) * 1000)))
#     outintegrated = add_suffix_and_join(args.p4file, 'integrated', outdir)
#     start = time.time()
#     subprocess.check_call([args.bf4_exec, '--render-integration', outintegrated,
#             '--integration-template', int_file, '--render-only', outexpd],
#         stderr=DEVNULL, stdout=DEVNULL)
#     end = time.time()
#     print('done integration in {}ms'.format(int((end - start) * 1000)))
#     print('All set. To run bf4:')
#     print('{} {}'.format(args.bf4_exec, outintegrated))

# for l in reader(fin):
#     if len(l) < 2:
#         print('expecting <file>,v1')
#         continue
#     file = os.path.abspath(l[0])
#     ver = version(file)
#     if ver == 0:
#         print('can\'t tell version for {}'.format(file))
#         continue
#     p = os.path.basename(file)
#     p=os.path.splitext(p)[0]
#     inkind = l[1]
#     dname = '{}_{}'.format(p, inkind)
#     dname = os.path.join(outdir, dname)
#     if not os.path.exists(dname):
#         os.makedirs(dname)
#     arglist=['p4c-bm2-ss']
#     print('{} version {}'.format(p, ver))
#     if ver == 14:
#         arglist.extend(['--std', 'p4-14'])
#     arglist.extend(['--make-field-lists', '{}-with-fieldlists.p4'.format(p)])
#     arglist.append(file)
#     cleanlog=open(os.path.join(dname, 'cleanup_log.txt'), 'w')
#     try:
#         subprocess.check_call(arglist, cwd=dname, stderr = cleanlog, stdout = cleanlog)
#     except:
#         print('failed to cleanup for {}'.format(p))
#         continue
#     finally:
#         cleanlog.close()
#     kwork = os.path.abspath(os.path.join('.', 'kitchen_work.sh'))
#     v1int = os.path.abspath(os.path.join('v1_integration.p4'))
#     arglist = [kwork, '{}-with-fieldlists.p4'.format(p), v1int, '.']
#     kitchenlog=open(os.path.join(dname, 'kitchen_log.txt'), 'w')
#     try:
#         subprocess.check_call(arglist, cwd=dname, stderr = kitchenlog, stdout = kitchenlog)
#     except:
#         print('failed to do kitchen work for {}'.format(p))
#         continue
#     print('ok for {}'.format(p))