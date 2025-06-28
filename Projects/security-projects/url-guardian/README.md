# URL Guardian

URL Guardian is an AI-powered URL security analysis tool that helps users determine whether a given URL is safe or potentially malicious. The application uses machine learning models to analyze various features of URLs and provide a threat score along with security warnings.

## Features

- **URL Analysis**: Analyze URLs for phishing threats based on various security features.
- **Threat Scoring**: Provides a threat score indicating the likelihood of a URL being malicious.
- **Security Warnings**: Displays warnings for suspicious characteristics of the URL.
- **User -Friendly Interface**: Simple and intuitive web interface for easy interaction.

## Technologies Used

- **Flask**: Web framework for building the application.
- **XGBoost**: Machine learning model for URL classification.
- **Pandas**: Data manipulation and analysis.
- **NumPy**: Numerical computing.
- **Joblib**: Model serialization.
- **TLDExtract**: Extracts top-level domain from URLs.
- **HTML/CSS**: Frontend design using Tailwind CSS.

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Clone the Repository

```bash
git clone https://github.com/VemuluriChethan/My-Projects.git
cd My-Projects
```

### Install Dependencies

Create a virtual environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

Install the required packages:

```bash
pip install -r requirements.txt
```

### Model Training

Before running the application, you need to train the model. Run the following command:

```bash
python train.py
```

This will generate the necessary model files in the `models` directory.

## Running the Application

To start the Flask application, run:

```bash
python app.py
```

The application will be accessible at `http://127.0.0.1:5000`.

## Usage

1. Open your web browser and navigate to `http://127.0.0.1:5000`.
2. Enter the URL you want to analyze in the input field.
3. Click on the "Analyze URL" button.
4. Review the results, including the threat score and any security warnings.

## Health Check Endpoint

You can check the health of the application by navigating to `http://127.0.0.1:5000/health`. This endpoint will return the status of the model and the number of features loaded.

## License

This project is licensed under the MIT License.

## Acknowledgments

- [Flask](https://flask.palletsprojects.com/) for the web framework.
- [XGBoost](https://xgboost.readthedocs.io/) for the machine learning model.
- [Pandas](https://pandas.pydata.org/) and [NumPy](https://numpy.org/) for data manipulation.
- [Tailwind CSS](https://tailwindcss.com/) for styling the frontend.

---

Feel free to modify any sections to better fit your project or add any additional information that you think is necessary!
