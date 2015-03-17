# =============================================================================
# >> CLASSES
# =============================================================================
class Search(object):
    '''
    This class is used to search for the Windows equivalent of a Linux
    function.
    '''

    def __init__(self, linux_db, windows_db, linux_func_ea, linux_func):
        '''
        Initializes the Search object.

        @param linux_db The Linux database.
        @param windows_db The Windows database.
        @param linux_func_ea The identifier of the Linux function.
        @param linux_func The Linux function.
        '''

        self.linux_db = linux_db
        self.windows_db = windows_db
        self.linux_func_ea = linux_func_ea
        self.linux_func = linux_func

        # Get all strings of this function as we don't want to do that for
        # every Windows function.
        self.linux_func_strings = linux_db.get_function_strings(linux_func)

    def search(self, exact_matches_only=False):
        '''
        Starts the search for the equivalent.
        '''

        possible_functions = set(self._get_exact_matches())
        if not possible_functions:
            return set()

        if len(possible_functions) == 1:
            # No need to filter a single result
            return possible_functions

        # Try to filter the possible functions
        possible_functions = set(
            self._filter_possible_functions(possible_functions))

        # If we still got multiple matches, but only want to search for exact
        # matches, return an empty set
        if exact_matches_only and len(possible_functions) > 1:
            return set()

        return possible_functions

    def _get_exact_matches(self):
        '''
        Returns all functions which have matching strings.
        '''

        return ((win_func_ea, win_func) for win_func_ea, win_func in self.windows_db.functions.iteritems() \
            if self.windows_db.get_function_strings(win_func) == self.linux_func_strings)

    def _filter_possible_functions(self, possible_functions):
        '''
        Filter all functions by comparing the strings of their caller
        functions.
        '''

        return ((win_func_ea, win_func) for win_func_ea, win_func in possible_functions \
            if self._check_possible_function(win_func_ea, win_func))

    def _check_possible_function(self, win_func_ea, win_func):
        '''
        Check the function by comparing the strings of the caller functions.
        '''

        for linux_xref_func_ea in self.linux_func.xrefs_to:
            linux_xref_func_strings = self.linux_db.get_function_strings(
                self.linux_db.get_function_by_ea(linux_xref_func_ea))
            for win_xref_func_ea in win_func.xrefs_to:
                if self.windows_db.get_function_strings(
                        self.windows_db.get_function_by_ea(
                        win_xref_func_ea)) == linux_xref_func_strings:
                    break
            else:
                return False
        return True