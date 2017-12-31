class bcolors:
    """
    Utility to add colors to shell for scripts
    """
    HEADERS = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    INFO = '{info}[INFO]{endc}'.format(info=OKBLUE, endc=ENDC)
    ACTION = '{info}[ACTION]{endc}'.format(info=OKBLUE, endc=ENDC)
    SUCCESS = '{green}[SUCCESS]{endc}'.format(green=OKGREEN, endc=ENDC)
    FAIL = '{red}[FAIL]{endc}'.format(red=FAIL, endc=ENDC)
