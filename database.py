# =============================================================================
# >> IMPORTS
# =============================================================================
# IDA
from idautils import Strings
from idautils import Functions
from idautils import XrefsTo

from idc import GetFunctionName
from idc import GetFunctionAttr
from idc import GetFuncOffset
from idc import FUNCATTR_START


# =============================================================================
# >> CLASSES
# =============================================================================
class Database(object):
    '''
    Stores information about the current analysed file.
    '''

    def __init__(self):
        '''
        Initializes the database.
        '''

        self.functions = {}
        self.strings = {}

    def get_function_by_name(self, name):
        '''
        Returns the function's ea and corresponding Function object.

        @param <name>:
        The name of the function
        '''

        for ea, function in self.functions.iteritems():
            if function.name == name:
                return (ea, function)

        return (None, None)

    def get_function_strings(self, function):
        '''
        Returns a tuple with all strings withing the given Function object.

        @param <function>:
        A Function object.
        '''

        return set(self.strings[ea] for ea in function.strings)
        
    def get_function_by_ea(self, ea):
        '''
        Retrieves a Function object from an ea.
        '''
        
        return self.functions[ea]

    def remove_string(self, ea):
        '''
        Removes a string from the database.
        '''

        # Delete from strings dict
        del self.strings[ea]

        # Remove all references in the function set
        for function in self.functions.itervalues():
            function.strings.discard(ea)


class Function(object):
    '''
    Represents a function.
    '''

    def __init__(self, name, strings, xrefs_to, pretty_name):
        '''
        Initializes the object.

        @param <name>:
        The name or symbol of the function.

        @param <string>:
        A set of addresses to strings.

        @param <xrefs_to>:
        A set of addresses to functions which call this function.

        @param <pretty_name>:
        A pretty name for the function.
        '''

        self.name = name
        self.strings = strings
        self.xrefs_to = xrefs_to
        self.pretty_name = pretty_name


# =============================================================================
# >> FUNCTIONS
# =============================================================================
def analyse_file():
    '''
    Analyses the current file and creates a new database for the found
    information.
    '''
    
    print 'Analysing file...'
    database = Database()
    
    # Fill the database with strings
    strings = database.strings
    for string in Strings():
        try:
            strings[string.ea] = str(string)
        except TypeError:
            strings[string.ea] = None

    # Fill the database with functions
    functions = database.functions
    for ea in Functions():
        functions[ea] = analyse_function(ea)

    # Add all function strings
    add_function_strings(functions, strings)

    print 'Functions:', len(database.functions)
    print 'Strings:', len(database.strings)
    
    return database


def analyse_function(ea):
    '''
    Analyses a function and returns a new Function object.

    @param <ea>:
    The start address of the function.
    '''

    return Function(
        GetFunctionName(ea),
        set(),
        set(get_xref_to_calls(ea)),
        GetFuncOffset(ea)
    )

def get_xref_to_calls(ea):
    '''
    Returns all function addresses which call the given function.

    @param <ea>:
    The start address of the function.
    '''

    # Loop through all references to this function
    for xref in XrefsTo(ea):
        # Not a Code_Far_Call or Code_Near_Call?
        if xref.type not in (16, 17):
            continue

        yield xref.to

def add_function_strings(functions, strings):
    '''
    Adds the strings to the functions that use them.
    '''

    for ea in strings.keys():
        references = tuple(XrefsTo(ea))

        # Is there no reference to this string?
        if not references:
            # No need to keep it
            del strings[ea]
            continue

        del_count = 0

        # Loop through all references
        for xref in references:
            func_ea = GetFunctionAttr(xref.frm, FUNCATTR_START)

            # Is the reference not a function?
            # Actually, we should compare func_ea == -1, but this seems to be
            # buggy. The -1 is probably returned as an unsigned int, which
            # results in 4294967295.
            if func_ea == 4294967295:
                del_count += 1

                # Skip it
                continue

            functions[func_ea].strings.add(ea)

        # No reference to a function?
        if del_count == len(references):
            del strings[ea]