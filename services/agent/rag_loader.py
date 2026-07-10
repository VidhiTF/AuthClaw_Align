import os


def load_compliance_docs():

    docs = []

    data_folder = "data"

    for file_name in os.listdir(data_folder):

        file_path = os.path.join(
            data_folder,
            file_name
        )

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            docs.append(
                file.read()
            )

    return "\n\n".join(docs)