import os


script_cwd = os.path.dirname(os.path.abspath(__file__))

def file_exists(path):
    return path is not None and os.path.isfile(path)


def file_finder(executable):
    if file_exists(executable):
        return executable

    for path in os.environ['PATH'].split(os.pathsep):
        procmon_path = os.path.join(path.strip('"'), executable)

        if file_exists(procmon_path):
            return procmon_path

    if file_exists(os.path.join(script_cwd, executable)):
        return os.path.join(script_cwd, executable)

    return None