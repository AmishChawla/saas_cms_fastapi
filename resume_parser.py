from pyresparser import ResumeParser
import warnings
import pandas as pd
warnings.filterwarnings('ignore')
# import en_core_web_sm
import xml.etree.ElementTree as ET
import xml.dom.minidom

# nlp = en_core_web_sm.load()

def list_of_dicts_to_xml(data_list, root_name='data', item_name='resume'):
    root = ET.Element(root_name)
    for data_dict in data_list:
        item = ET.Element(item_name)
        root.append(item)
        _dict_to_xml(data_dict, item)

    xml_string = ET.tostring(root, encoding='utf8', method='xml').decode('utf8')
    dom = xml.dom.minidom.parseString(xml_string)
    prettified_xml = dom.toprettyxml(indent='    ')

    return prettified_xml

def _dict_to_xml(dictionary, parent):
    for key, value in dictionary.items():
        if isinstance(value, list):
            # If the value is a list, create an element for each item in the list
            for item in value:
                child = ET.Element(key)
                child.text = item
                parent.append(child)
        elif isinstance(value, dict):
            # Recursively convert nested dictionaries
            child = ET.Element(key)
            parent.append(child)
            _dict_to_xml(value, child)
        else:
            # For simple key-value pairs
            child = ET.Element(key)
            child.text = str(value)
            parent.append(child)

async def extract_data(file_paths):
    result = []
    for file_path in file_paths:
        data = ResumeParser(file_path).get_extracted_data()
        result.append(data)

    # Convert the extracted data to a Pandas DataFrame
    df = pd.DataFrame(result)

    # Save DataFrame to CSV
    csv_file_path = 'output.csv'
    df.to_csv(csv_file_path, index=False)

    xml_file_path = 'output.xml'
    xml_data = list_of_dicts_to_xml(result)
    with open(xml_file_path, 'w', encoding='utf-8') as xml_file:
        xml_file.write(xml_data)

    return result, csv_file_path, xml_file_path


# result = extract_data([
# 'resumes/AmishChawla_20CE1020.pdf',
# 'resumes/AryanLakde_20CE1118.pdf',
# 'resumes/CV_AmishChawla.pdf',
# ])

