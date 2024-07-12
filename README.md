Gets ALL findings for an application profile.

*Note*: This script requires Python 3!

## Setup

Clone this repository:

    git clone https://github.com/cadonuno/extractallfindings

Install dependencies:

    cd extractallfindings
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    py extract_findings.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    py extract_findings.py (arguments)

Arguments supported include:
- `-t`, `--target` - (mandatory) File to save results - must be .xlsx.
- `-s`, `--sast` Set to enable fetching of SAST results.
- `-d`, `--dast` Set to enable fetching of DAST results.
- `-c`, `--sca` Set to enable fetching of SCA results.
- `-v`, `--verbose` Set to enable verbose logging.

## Results
The results will be saved to a .xlsx file.
