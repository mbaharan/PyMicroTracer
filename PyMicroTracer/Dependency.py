"""
        Project: PyDGP
        File name: Dependency
        Author: mbaharan -- 
        Email: 
        University of North Carolina at Charlotte
        Date:          Jan 12, 2018-4:05 PM
        Arguments:
        Outputs:
        Dependencies: 
"""
import PyMicroTracer.Constant as cnst


class Dependency(object):
    '''
        Class name:  Dependency
        Description: It capsulates the dependency between instructions.
        Date added: Dec 4, 2017-9:56:35 AM
    '''

    def __init__(self, dependent, dependency_type):
        '''
        Constructor
        '''
        self.dependent = dependent
        self.dependency_type = dependency_type

    def __str__(self):
        return self.dependent + " (" + cnst.dep_name(self.dependency_type) + ")"

    def __repr__(self):
        return self.dependent + " (" + cnst.dep_name(self.dependency_type) + ")"


if __name__ == "__main__":
    DUT = Dependency("rdx", cnst.dep_raw())
    print(str(DUT))
