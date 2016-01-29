# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle


# =============================================================================
# >> FUNCTIONS
# =============================================================================
class Search(object):
    """A class that implements various search mechanisms."""

    def __init__(self, linux_db, windows_db):
        """Initialize the object.

        :param Database linux_db: Linux database.
        :param Database windows_db: Windows database.
        """
        self.linux_db = linux_db
        self.windows_db = windows_db

    def discover(self):
        """Discover Windows functions.

        :return: All found Windows functions.
        :rtype: generator
        """
        if not self.windows_db.functions:
            raise ValueError('Windows database has no function.')

        total_count = 0
        while True:
            count = self._string_match_search()
            if count == 0:
                break

            total_count += count

        percentage = 100. / len(self.windows_db.functions) * total_count
        print 'Found {0} ({1:.3}%) functions in total!'.format(
            total_count, percentage)
        for func in self.windows_db.functions.itervalues():
            if func.renamed:
                yield (func.ea, func.symbol)

    def _string_match_search(self):
        """Discover functions by searching for strings matches.

        :return: Number of discovered functions.
        :rtype: int
        """
        print 'String match search...'
        count = 0
        for linux_func in self.linux_db.functions.itervalues():
            if not linux_func.string_eas:
                # No need to compare functions, which don't contain strings.
                # We would get tons of multi-matches, but not a single result.
                continue

            result = None
            for windows_func in self.windows_db.functions.itervalues():
                # Skip already renamed functions
                if windows_func.renamed:
                    continue

                # Skip functions that do not have the same strings
                if linux_func.strings != windows_func.strings:
                    continue

                if result is not None:
                    # Multi-match :(
                    break

                result = windows_func
            else:
                # No multi-match! Found a function?
                if result is not None:
                    result.rename(linux_func)
                    count += 1 + self._single_xref_search(linux_func, result)

        print 'Found {0} functions.'.format(count)
        return count + self._multiple_xrefs_search()

    def _multiple_xrefs_search(self):
        """Search for functions by comparing the caller functions of a not
        renamed function.

        :return: Number of discovered functions.
        :rtype: int
        """
        # TODO: Here is something wrong. It doesn't find a single function...
        print 'Multiple xrefs search...'
        count = 0

        for windows_func in self.windows_db.functions.itervalues():
            if windows_func.renamed:
                continue

            usable_xrefs_to = list(self._get_usable_xrefs_to(windows_func))
            if not usable_xrefs_to:
                continue

            possible_functions = self.linux_db.get_function_by_symbol(
                usable_xrefs_to.pop(0).symbol).xrefs_from
            for win_xref_to in self._get_usable_xrefs_to(windows_func):
                possible_functions.itersection_update(
                    self.linux_db.get_function_by_symbol(
                        win_xref_to.symbol).xrefs_from)

                if not possible_functions:
                    break

                if len(possible_functions) > 1:
                    continue

                linux_func = possible_functions.pop()
                windows_func.rename(linux_func)
                count += 1 + self._single_xref_search(
                    linux_func, windows_func)
                break

        print 'Found {0} functions.'.format(count)
        return count

    @staticmethod
    def _get_usable_xrefs_to(windows_func):
        """Return all renamed functions that call the given function.

        :param Function windows_func: Function to get its callers from.
        :rtype: generator
        """
        for func in windows_func.xrefs_to:
            if func.renamed:
                yield func

    def _single_xref_search(self, linux_func, windows_func):
        """Do an xref search in both directions.

        If there is only one caller/callee left, it can be safely renamed.

        :param Function linux_func: A Linux function.
        :param Function windows_func: Equivalent of the Linux function.
        :return: Number of discovered functions.
        :rtype: int
        """
        xref_to_count = self._single_xref_to_search(linux_func, windows_func)
        if xref_to_count > 0:
            print 'Found {0} xref_to functions.'.format(xref_to_count)

        xref_from_count = self._single_xref_from_search(
            linux_func, windows_func)
        if xref_from_count > 0:
            print 'Found {0} xref_from functions.'.format(xref_from_count)

        return xref_to_count + xref_from_count

    def _single_xref_to_search(self, linux_func, windows_func):
        """.. seealso:: :meth:`_single_xref_search`"""
        return self._single_xref_attr_search(
            'xrefs_to', linux_func, windows_func)

    def _single_xref_from_search(self, linux_func, windows_func):
        """.. seealso:: :meth:`_single_xref_search`"""
        return self._single_xref_attr_search(
            'xrefs_from', linux_func, windows_func)

    def _single_xref_attr_search(self, attr, linux_func, windows_func):
        """.. seealso:: :meth:`_single_xref_search`"""
        length = len(linux_func.xref_to_eas)
        if length == 0:
            return 0

        if length != len(windows_func.xref_to_eas):
            return 0

        result = None
        key = lambda func: func.symbol
        for linux_xref, windows_xref in zip(
                sorted(getattr(linux_func, attr), key=key),
                sorted(getattr(windows_func, attr), key=key)):
            if windows_xref.renamed:
                if windows_xref.symbol != linux_xref.symbol:
                    return 0

                continue

            if result is not None:
                # Multiple not renamed xrefs
                return 0

            result = (linux_xref, windows_xref)

        if result is not None:
            linux_xref, windows_xref = result
            windows_xref.rename(linux_xref)
            return 1 + self._single_xref_from_search(linux_xref, windows_xref)

        return 0


# =============================================================================
# >> MAIN
# =============================================================================
def main():
    """Discover Windows functions based on the cleaned database."""
    cleaned_up_path = AskFile(0, '*.db', 'Select the cleaned up database')
    if cleaned_up_path is None:
        return

    print 'Loading cleaned up database...'
    with open(cleaned_up_path, 'rb') as f:
        linux_db, windows_db = pickle.load(f)

    print 'Database has been loaded!'

    discovered_path = AskFile(
        1, '*.db', 'Select a destination for the discovered database')
    if discovered_path is None:
        return

    result = tuple(Search(linux_db, windows_db).discover())
    print 'Saving discovered database...'
    with open(discovered_path, 'wb') as f:
        pickle.dump(result, f)

    print 'Database has been saved!'

if __name__ == '__main__':
    main()