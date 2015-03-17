# =============================================================================
# >> IMPORTS
# =============================================================================
# Python
import cPickle as pickle

# win_discoverer
from database import analyse_file


# =============================================================================
# >> MAIN ROUTINE
# =============================================================================
def main():
    '''
    Analyses a binary file and saves the data to the given file.
    '''

    # Ask the user for a file to save
    file_path = AskFile(1, '*.db', 'Select a destination for the database')

    # Did the user canceled the dialog?
    if file_path is None:
        return

    # Analyse the file
    database = analyse_file()

    # Save the data to the file
    print 'Saving data to file...'
    with open(file_path, 'wb') as f:
        pickler = pickle.Pickler(f, -1)
        pickler.fast = True
        pickler.dump(database)

    print 'Done!'

if __name__ == '__main__':
    main()