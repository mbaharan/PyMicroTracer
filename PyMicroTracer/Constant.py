'''
    Author: Mohammadreza Baharani
    Email: mbaharan@uncc.edu
    University of North Carolina at Charlotte
    Date:          Dec 1, 2017-10:36:03 AM
    Arguments:
    Outputs:
    Dependencies:
'''

DependencyName = ["RAR", "RAW", "WAR", "WAW", "NA"]


def is_it_shredded_register(reg_id):
    """
    01: X86_REG_AH,
    02: X86_REG_AL,
    03: X86_REG_AX,<-
    04: X86_REG_BH,
    05: X86_REG_BL,
    06: X86_REG_BP,<-
    07: X86_REG_BPL,
    08: X86_REG_BX,<-
    09: X86_REG_CH,
    10: X86_REG_CL,
    11: X86_REG_CS,
    12: X86_REG_CX,<-
    13: X86_REG_DH,
    14: X86_REG_DI,<-
    15: X86_REG_DIL,
    16: X86_REG_DL,
    17: X86_REG_DS,
    18: X86_REG_DX,
    19: X86_REG_EAX,<-
    20: X86_REG_EBP,<-
    21: X86_REG_EBX,<-
    22: X86_REG_ECX,<-
    23: X86_REG_EDI,<-
    24: X86_REG_EDX,
    25: X86_REG_EFLAGS,
    26: X86_REG_EIP,
    27: X86_REG_EIZ,
    28: X86_REG_ES,
    29: X86_REG_ESI,<-
    30: X86_REG_ESP,<-
    31: X86_REG_FPSW,
    32: X86_REG_FS,
    33: X86_REG_GS,
    34: X86_REG_IP,
    35: X86_REG_RAX,<-
    36: X86_REG_RBP,<-
    37: X86_REG_RBX,<-
    38: X86_REG_RCX,<-
    39: X86_REG_RDI,<-
    40: X86_REG_RDX,<-
    41: X86_REG_RIP,
    42: X86_REG_RIZ,
    43: X86_REG_RSI,<-
    44: X86_REG_RSP,<-
    45: X86_REG_SI,<-
    46: X86_REG_SIL,
    47: X86_REG_SP,<-
    48: X86_REG_SPL,
    49: X86_REG_SS,
    50: X86_REG_CR0,
    """
    val = []

    # AL, AH, AX, EAX
    a_family = [1, 2, 3, 19, 35]
    if reg_id in a_family:
        val = a_family

    # BL, BH, BX, EBX
    b_family = [4, 5, 8, 21, 37]
    if reg_id in b_family:
        val = b_family

    # CH, CL, BX, ECX
    c_family = [9, 10, 12, 22, 38]
    if reg_id in c_family:
        val = c_family

    # DH, DL, DX, EDX
    d_family = [13, 16, 18, 24, 40]
    if reg_id in d_family:
        val = d_family

    # SP, ESP
    sp_family = [47, 30, 44]
    if reg_id in sp_family:
        val = sp_family

    # BP, EBP
    bp_family = [6, 20, 36]
    if reg_id in bp_family:
        val = bp_family

    # SI, ESI
    si_family = [45, 29, 43]
    if reg_id in si_family:
        val = si_family

    # DI, EDI
    di_family = [14, 23, 39]
    if reg_id in di_family:
        val = di_family

    return val


def dep_waw():
    return 3


def dep_war():
    return 2


def dep_raw():
    return 1


def fail():
    return -1


def success():
    return 0


def dep_rar():
    return 0


def dep_name(type_index):
    if not type_index < 0 and type_index <= 3:
        return DependencyName[type_index]
    else:
        return DependencyName[4]


if __name__ == "__main__":
    print(fail())
    print(dep_name(dep_raw()))
    print(dep_name(9))
