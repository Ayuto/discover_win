# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle


# =============================================================================
# >> FUNCTIONS
# =============================================================================
def rename_functions(exact_matches, multiple_matches):
    '''
    Renames functions based on a discovered database.
    '''

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
    Renames Windows functions based on the given database.
    '''

    discovered_path = AskFile(0, '*.db', 'Select the discovered database')
    if discovered_path is None:
        return

    with open(discovered_path, 'rb') as f:
        exact_matches, multiple_matches = pickle.load(f)

    rename_functions(exact_matches, multiple_matches)

if __name__ == '__main__':
    main()