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
    """Ask for a file, analyse the currently opened database and save it."""
    file_path = AskFile(1, '*.db', 'Select a destination for the database')
    if file_path is None:
        print 'Script has been cancelled.'
        return

    database = Database()
    print 'Strings:', len(database.strings)
    print 'Functions:', len(database.functions)
    database.save(file_path)


if __name__ == '__main__':
    main()
