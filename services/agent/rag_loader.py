import os


def load_compliance_docs():
    docs = []
    data_folder = os.path.join(os.path.dirname(__file__), "data")

    for file_name in sorted(os.listdir(data_folder)):
        file_path = os.path.join(data_folder, file_name)
        if not os.path.isfile(file_path):
            continue
        with open(file_path, "r", encoding="utf-8") as file:
            docs.append(file.read())

    return "\n\n".join(docs)
