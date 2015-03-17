# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle

# search
from search import Search


# =============================================================================
# >> CONSTANTS
# =============================================================================
# Set this to the number of multi matches you would like to have. If you
# don't want any multi matches, set this value to 1
MAX_MULTI_MATCH = 5


# =============================================================================
# >> FUNCTIONS
# =============================================================================
def discover_functions(linux_db, windows_db):
    '''
    Discovers and renames Windows functions based on the given databases.
    '''

    exact_matches = []
    multiple_matches = []

    print 'Discovering functions...'
    linux_function_items = linux_db.functions.items()
    item_count = len(linux_function_items)
    for index, data in enumerate(linux_function_items):
        linux_func_ea, linux_func = data
        print '[{0}/{1}] Checking for {2}...'.format(
            index+1, item_count, linux_func.pretty_name)

        possible_functions = Search(
            linux_db, windows_db, linux_func_ea, linux_func).search()

        match_count = len(possible_functions)
        if match_count == 0 or match_count > MAX_MULTI_MATCH:
            continue

        elif match_count == 1:
            win_func_ea, win_func = tuple(possible_functions)[0]
            exact_matches.append((linux_func, win_func_ea, win_func))

        else:
            multiple_matches.append((linux_func, possible_functions))

    count = 0

    print 'Adding multiple matches...'
    for linux_func, possible_functions in multiple_matches:
        for index, data in enumerate(possible_functions):
            win_func_ea, win_func = data

            if (linux_func, win_func_ea, win_func) in exact_matches:
                continue

            comment = GetFuncOffset(win_func_ea)
            if not comment.startswith('sub_'):
                continue

            new_comment = 'MultiMatch_{0}'.format(linux_func.pretty_name)
            SetFunctionCmt(win_func_ea, new_comment, 1)
            MakeName(win_func_ea, 'MultiMatch{0}_{1}'.format(index, linux_func.name))
            print 'Renaming {0} to {1}'.format(comment, new_comment)
            count += 1

    print 'Adding exact matches...'
    for linux_func, win_func_ea, win_func in exact_matches:
        comment = GetFuncOffset(win_func_ea)
        if not comment.startswith('sub_'):
            continue

        SetFunctionCmt(win_func_ea, linux_func.pretty_name, 1)
        MakeName(win_func_ea, linux_func.name)
        print 'Renaming {0} to {1}'.format(comment, linux_func.pretty_name)
        count += 1

    print 'Renamed {0} functions!'.format(count)


# =============================================================================
# >> MAIN ROUTINE
# =============================================================================
def main():
    '''
    Discovers Windows functions based on the given database.
    '''

    cleaned_up_path = AskFile(0, '*.db', 'Select the cleaned up database')
    if cleaned_up_path is None:
        return

    with open(cleaned_up_path, 'rb') as f:
        linux_db, windows_db = pickle.load(f)

    discover_functions(linux_db, windows_db)

if __name__ == '__main__':
    main()