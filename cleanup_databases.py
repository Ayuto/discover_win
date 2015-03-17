# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle


# =============================================================================
# >> FUNCTIONS
# =============================================================================
def cleanup_databases(linux_db, windows_db):
    '''
    Cleans up both databases.
    '''

    # Only keep shared strings
    print 'Cleaning up Linux database...'
    win_strings = windows_db.strings.values()
    for ea, string in linux_db.strings.items():
        if string not in win_strings:
            linux_db.remove_string(ea)

    print 'Cleaning up Windows database...'
    linux_strings = linux_db.strings.values()
    for ea, string in windows_db.strings.items():
        if string not in linux_strings:
            windows_db.remove_string(ea)

            
# =============================================================================
# >> MAIN ROUTINE
# =============================================================================
def main():
    '''
    Cleans up and merges the specified databases and saves the result to a
    new file.
    '''
    
    # Step 1 - Linux file
    linux_db_path = AskFile(0, '*.db', 'Select the Linux database')
    if linux_db_path is None:
        return

    with open(linux_db_path, 'rb') as f:
        linux_db = pickle.load(f)
    
    # Step 2 - Windows file
    windows_db_path = AskFile(0, '*.db', 'Select the Windows database')
    if windows_db_path is None:
        return

    with open(windows_db_path, 'rb') as f:
        windows_db = pickle.load(f)
        
    # Step 3 - Shared cleaned up file
    cleaned_up_path = AskFile(1, '*.db', 'Select the cleaned up database')
    if cleaned_up_path is None:
        return

    cleanup_databases(linux_db, windows_db)

    # Step 4 - Save cleaned up databases
    with open(cleaned_up_path, 'wb') as f:
        pickler = pickle.Pickler(f, -1)
        pickler.fast = True
        pickler.dump((linux_db, windows_db))

    print 'Done!'

if __name__ == '__main__':
    main()