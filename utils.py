import logging
import re
from os import remove, path, mkdir
from colorama import Fore, Back, Style
from datetime import datetime
from shutil import rmtree
from config import get_debug_mode, info_filename

# Get and format current timestamp
timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

# Create log directory if it doesn't already exist
if not path.exists('logs/'):
    try:
        mkdir('logs')
    except Exception as error:
        usr_log(str(error), "error")

# Initialize and format logging
logging.basicConfig(
    level=logging.INFO,
    filename=f"logs/aws-{timestamp}.log",
    format='%(asctime)s  %(levelname)-10s %(name)s %(message)s',
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging = logging.getLogger('run_newwebserver')


def usr_log(message, type='info'):
    """
    Handles various types of logging while displaying the message to the user

    Parameters:
            message - the message to log/display
            type - the type of message (i.e. info,success,error)
    """
    if type == 'info':
        print(Fore.CYAN + str(message))
        logging.info(str(message))
    elif type == 'success':
        print(Fore.GREEN + str(message))
        logging.info(str(message))
    elif type == 'error':
        print(Fore.RED + str(message))
        logging.error(str(message))
    elif type == 'debug':
        if get_debug_mode():
            print(Fore.YELLOW + str(message))
        logging.debug(str(message))
    else:
        print(str(message))
        logging.info(str(message))


def wait_func(func, *args):
    """
    Adds a 'press enter to continue...' prompt after each function call for use with menu

    Parameters:
            func - the function to run before the prompt
            *args - any arguments that should be passed to the function
    """
    logging.info(f"User called {func.__name__} from menu")
    func(*args)
    input("\nPress enter to continue...")


def user_choice(question):
    """
    Displays a 'yes/no' choice to the user and returns the result
    'Yes' is the default choice. 

    Parameters:
            question - the question to ask the user
    Returns:
            choice - the result of the choice as either True or False
    """

    # Display the question to the user
    print(f"{question}? [Yes/no]")

    # Define accepted values for 'no'
    no = {'no', 'n'}

    # Get the input and convert to lower-case
    choice = input().lower()

    # Return the choice
    if choice in no:
        return False
    else:
        return True


def write_simple_file(file_name, contents):
    """
    Write the contents of a variable to file, checking if it exists first

    Parameters:
            file_name: the name of the file to write
            contents: the contents of the file to write
    """

    # Remove if file already exists
    if(path.exists(file_name)):
        remove(file_name)

    try:
        file = open(file_name, "w+")
        file.write(contents)
        file.close()
    except Exception as error:
        usr_log(f'File Creation Error: {error}', 'error')


def create_info_file(instance, bucket):
    """
    Create a local info file which lists the most recent instance and bucket created by the script

    Returns:
            file - the file that was created
    """

    # Remove the file if it already exists
    if(path.exists(info_filename)):
        remove(info_filename)

    # Write the new file with the insstance id on line 1 and bucket name on line 2
    file = open(info_filename, "a+")
    file.write(instance.id+"\n")
    if bucket != None:
        file.write(bucket.name)
    file.close()
    return file


def input_string_format(prompt, existing_value, replace_spaces=True, space_char='-', min_len=5):
    """
    Gets a string input from the user and formats it using RegEx

    Parameters:
            prompt - the question to ask the user
            existing_value - the current value of the variable being changed
            replace_spaces - if the function should replace spaces with another char
            space_char - the char to replace spaces with
            min_len - the minimum length for the string to be considered valid
    Return:
            usr_input - the formatted string
    """
    regex = r"([^a-zA-Z0-9\-\_])"  # RegEx of accepted chars
    usr_input = str(input(f"{prompt} [{existing_value}]: "))  # Display user prompt
    if replace_spaces:
        usr_input = usr_input.strip()  # remove trailing and leadaing whitespace
        usr_input = usr_input.replace(' ', space_char)  # replace spaces with defined char
    usr_input = re.sub(regex, '', usr_input)  # Remove any chars that do not match the RegEx

    # If the length is below min_len or if the user enters nothing, use existing value
    if len(usr_input) < min_len:
        usr_input = existing_value
        usr_log(f"Using existing value, invalid/empty user input!", "error")
    usr_log(f"{prompt}: '{usr_input}'", "info")

    return usr_input


def clear_logs():
    """
    Check if the logs folder exists and delete it
    """

    # Check that logs folder exists
    if path.exists('logs/'):
        # Attempt to delete the folder and display the result
        try:
            rmtree('logs/')
            usr_log("Logs directory deleted!", "success")
        except Exception as error:
            usr_log("clear_logs" + str(error), "error")
    else:
        usr_log("Nothing to delete. Logs folder doesn't exist!", "info")
