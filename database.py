# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle

# IDA
try:
    import idaapi

    from idautils import Strings
    from idautils import Functions
    from idautils import XrefsTo
    from idautils import FuncItems
    from idautils import XrefsFrom

    from idc import GetFunctionName
    from idc import GetFunctionAttr
    from idc import GetFuncOffset
    from idc import FUNCATTR_START

    CALL_JUMP_FLAGS = (
        idaapi.fl_CF,
        idaapi.fl_CN,
        idaapi.fl_JF,
        idaapi.fl_JN,
    )
except ImportError:
    print 'Script has been called outside of IDA.'


# =============================================================================
# >> CLASSES
# =============================================================================
class Database(object):
    """Create a pickle-able database of the analysed binary."""

    def __init__(self):
        """Initialize the database."""
        # {<function ea>: <Function object>, ...}
        self.functions = {}

        # {<string ea>: <str or None>, ...}
        self.strings = {}

        print 'Creating database...'
        self._fill_strings()
        self._fill_functions()
        self._add_function_strings()
        print 'Database has been created!'

    def _fill_strings(self):
        """Fill the ``strings`` dict."""
        strings = self.strings
        for string in Strings():
            try:
                strings[string.ea] = str(string)
            except TypeError:
                # I forgot when this can happen...
                continue

    def _fill_functions(self):
        """Fill the ``functions`` dict."""
        functions = self.functions
        for ea in Functions():
            if GetFunctionName(ea).startswith('_ZThn'):
                continue

            functions[ea] = Function(self, ea)

    def _add_function_strings(self):
        """Add the strings to the functions that use them."""
        for ea in self.strings.keys():
            references = tuple(XrefsTo(ea))
            del_count = 0
            for xref in references:
                func_ea = GetFunctionAttr(xref.frm, FUNCATTR_START)

                # Is the reference not a function?
                # Actually, we should compare func_ea == -1, but this seems to
                # be buggy. The -1 is probably returned as an unsigned int,
                # which results in 4294967295.
                if func_ea == 4294967295:
                    del_count += 1
                    continue

                self.get_function(func_ea).add_string(ea)

            # No need to keep strings without a reference or without a
            # reference to a function.
            if del_count == len(references):
                del self.strings[ea]

    def get_function_by_symbol(self, symbol):
        """Retrieve a function by its symbol.

        :param str symbol: Symbol of the function.
        :rtype: Function
        :raise ValueError: Raised when the symbol was not found.
        """
        for function in self.functions.itervalues():
            if function.symbol == symbol:
                return function

        raise ValueError('Symbol "{0}" not found.'.format(symbol))

    def get_function(self, ea):
        """Retrieve a function by its ea value."""
        return self.functions[ea]

    def remove_string(self, ea):
        """Remove a string from the database."""
        del self.strings[ea]
        for function in self.functions.itervalues():
            function.remove_string(ea)

    def get_string(self, ea):
        """Retrieve a string by its ea value."""
        return self.strings[ea]

    def save(self, file_path):
        """Pickle the database and save it to the given path.

        :param str file_path: Path to save the database at.
        """
        print 'Saving database...'
        with open(file_path, 'wb') as f:
            pickle.dump(self, f)

        print 'Database has been saved!'

    @staticmethod
    def load(file_path):
        """Load the database from the given file path.

        :param str file_path: Path of the saved database.
        """
        print 'Loading database...'
        with open(file_path, 'rb') as f:
            result = pickle.load(f)

        print 'Database has been loaded!'
        return result

    def cleanup(self, other):
        """Compare this database with the given one and remove all platform
        specific strings.

        :param Database other: Database to compare to.
        """
        print 'Cleaning up first database...'
        self._cleanup(other)
        print 'Cleaning up second database...'
        other._cleanup(self)
        print 'Databases have been cleaned up!'

    def _cleanup(self, other):
        self_strings = self.strings.values()
        for ea, string in other.strings.items():
            if string not in self_strings:
                other.remove_string(ea)


class Function(object):
    """Represents a function."""

    def __init__(self, database, ea):
        """Initialize the object.

        :param Database database: Database that stores this function.
        :param int ea: Start address of the function.
        """
        #: Database that stores this function
        self.database = database

        #: Start address of this function
        self.ea = ea

        #: Symbol of this function
        self.symbol = GetFunctionName(ea)

        #: Demangled name of this function
        self.demangled_name = GetFuncOffset(ea)

        #: All strings that are used in this function
        self.string_eas = set()
        self._strings = None

        #: All function addresses that call this function
        self.xref_to_eas = set(self._get_xref_to_calls(ea))
        self._xrefs_to = None

        #: All function addresses that are called by this function
        self.xref_from_eas = set(self._get_xref_from_calls(ea))
        self._xrefs_from = None

        #: Boolean that indicated if the function has been renamed
        self.renamed = False

    def add_string(self, ea):
        """Add a string to the function."""
        self.string_eas.add(ea)

    def remove_string(self, ea):
        """Remove a string from the function."""
        self.string_eas.discard(ea)

    def rename(self, linux_func):
        """Rename the function to its Linux equivalent.

        :param Function linux_func: The Linux equivalent of this function.
        """
        self.symbol = linux_func.symbol
        self.demangled_name = linux_func.demangled_name
        self.renamed = True

    @property
    def strings(self):
        """Return all strings contained by this function.

        :rtype: set
        """
        if self._strings is None:
            database = self.database
            self._strings = set(
                database.get_string(ea) for ea in self.string_eas)

        return self._strings

    @property
    def xrefs_to(self):
        """Return all functions that call this function.

        :rtype: set
        """
        if self._xrefs_to is None:
            database = self.database
            self._xrefs_to = set(
                database.get_function(ea) for ea in self.xref_to_eas)

        return self._xrefs_to

    @property
    def xrefs_from(self):
        """Return all functions that are called by this function.

        :rtype: set
        """
        if self._xrefs_from is None:
            database = self.database
            self._xrefs_from = set(
                database.get_function(ea) for ea in self.xref_from_eas)

        return self._xrefs_from

    @staticmethod
    def _get_xref_to_calls(ea):
        """Return a generator to iterate over all function addresses which
        call the given function.

        :param int ea: Start address of the function.
        """
        for xref in XrefsTo(ea):
            if xref.type not in CALL_JUMP_FLAGS:
                continue

            if GetFunctionName(xref.to).startswith('_ZThn'):
                continue

            yield xref.to

    def _get_xref_from_calls(self, ea):
        """Return a generator to iterate over all function address that are
        called in the given function address.

        :param int ea: Start address of the function.
        """
        # Code has been taken from here: https://github.com/darx0r/Reef
        for item in FuncItems(ea):
            for ref in XrefsFrom(item):
                if ref.type not in CALL_JUMP_FLAGS:
                    continue

                if ref.to in FuncItems(ea):
                    continue

                # call loc_<label name> and other stuff we don't want
                if ref.to not in self.database.functions:
                    continue

                yield ref.to
