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
def discover_functions(linux_db, windows_db, discover_db_path):
    '''
    Discovers Windows functions based on the given databases.
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

    print 'Found {0} multiple matches.'.format(len(multiple_matches))
    print 'Found {0} exact matches.'.format(len(exact_matches))

    print 'Saving database...'
    with open(discover_db_path, 'wb') as f:
        pickler = pickle.Pickler(f, -1)
        pickler.fast = True
        pickler.dump((exact_matches, multiple_matches))

    print 'Database has been saved!'


# =============================================================================
# >> MAIN ROUTINE
# =============================================================================
def unpack_and_discover(cleaned_up_path, file_path):
    with open(cleaned_up_path, 'rb') as f:
        linux_db, windows_db = pickle.load(f)

    discover_functions(linux_db, windows_db, file_path)

def main_ida():
    '''
    Discovers Windows functions based on the given database.
    '''
    cleaned_up_path = AskFile(0, '*.db', 'Select the cleaned up database')
    if cleaned_up_path is None:
        return

    file_path = AskFile(1, '*.db', 'Select a destination for the discovered database')
    if file_path is None:
        return

    unpack_and_discover(cleaned_up_path, file_path)

def main_normal(cleaned_up_path, file_path):
    unpack_and_discover(cleaned_up_path, file_path)

if __name__ == '__main__':
    try:
        import idautils
    except ImportError:
        import sys
        main_normal(*sys.argv[1:])
    else:
        main_ida()
