# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle

# discover_win
from database import Database


# =============================================================================
# >> MAIN
# =============================================================================
def main():
    """Cleanup and merge the linux and windows database into a single file."""
    # Step 1 - Linux file
    linux_db_path = AskFile(0, '*.db', 'Select the Linux database')
    if linux_db_path is None:
        return

    linux_db = Database.load(linux_db_path)

    # Step 2 - Windows file
    windows_db_path = AskFile(0, '*.db', 'Select the Windows database')
    if windows_db_path is None:
        return

    windows_db = Database.load(windows_db_path)

    # Step 3 - Shared cleaned up file
    cleaned_up_path = AskFile(1, '*.db', 'Select the cleaned up database')
    if cleaned_up_path is None:
        return

    linux_db.cleanup(windows_db)

    # Step 4 - Save cleaned up databases
    print 'Saving cleaned databases...'
    with open(cleaned_up_path, 'wb') as f:
        pickle.dump((linux_db, windows_db), f)

    print 'Done!'

if __name__ == '__main__':
    main()