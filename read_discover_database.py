# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle


# =============================================================================
# >> FUNCTIONS
# =============================================================================
def rename_functions(functions):
    """Rename unnamed functions in the binary using the given functions."""
    count = 0
    for ea, symbol in functions:
        # Skip functions with an auto-generated name
        if symbol.startswith('sub_'):
            continue
        
        # Skip names that have been renamed already (or already had a name)
        if not GetFunctionName(ea).startswith('sub_'):
            continue

        MakeName(ea, symbol)
        count += 1

    print 'Renamed {0} of {1} found functions'.format(count, len(functions))


# =============================================================================
# >> MAIN ROUTINE
# =============================================================================
def main():
    """Rename Windows functions based on the given database."""
    discovered_path = AskFile(0, '*.db', 'Select the discovered database')
    if discovered_path is None:
        return

    with open(discovered_path, 'rb') as f:
        functions = pickle.load(f)

    rename_functions(functions)

if __name__ == '__main__':
    main()
