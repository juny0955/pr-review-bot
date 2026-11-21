"""Apply resource limits in a fresh interpreter, then replace it with Git."""
import os
import resource
import sys

file_limit, cpu_limit = map(int, sys.argv[1:3])
resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
os.execvp(sys.argv[3], sys.argv[3:])
