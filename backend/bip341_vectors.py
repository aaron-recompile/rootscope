from __future__ import annotations

from dataclasses import dataclass

from .analyzer import AnalysisError, analyze_taproot


@dataclass(frozen=True)
class ScriptPathCase:
    script: str
    control_block: str


@dataclass(frozen=True)
class BIP341ScriptPathVector:
    case_id: int
    expected_address: str
    paths: list[ScriptPathCase]


# Source: https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
# We cover all script-path control-block examples from the scriptPubKey section.
SCRIPT_PATH_VECTORS: list[BIP341ScriptPathVector] = [
    BIP341ScriptPathVector(
        case_id=1,
        expected_address="bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586",
        paths=[
            ScriptPathCase(
                script="20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac",
                control_block="c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
            )
        ],
    ),
    BIP341ScriptPathVector(
        case_id=2,
        expected_address="bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5",
        paths=[
            ScriptPathCase(
                script="20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac",
                control_block="c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
            )
        ],
    ),
    BIP341ScriptPathVector(
        case_id=3,
        expected_address="bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm",
        paths=[
            ScriptPathCase(
                script="20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac",
                control_block="c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a",
            ),
            ScriptPathCase(
                script="06424950333431",
                control_block="faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7",
            ),
        ],
    ),
    BIP341ScriptPathVector(
        case_id=4,
        expected_address="bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq",
        paths=[
            ScriptPathCase(
                script="2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac",
                control_block="c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd82cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb",
            ),
            ScriptPathCase(
                script="07546170726f6f74",
                control_block="c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd864512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89",
            ),
        ],
    ),
    BIP341ScriptPathVector(
        case_id=5,
        expected_address="bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e",
        paths=[
            ScriptPathCase(
                script="2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac",
                control_block="c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553",
            ),
            ScriptPathCase(
                script="202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac",
                control_block="c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
            ),
            ScriptPathCase(
                script="207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac",
                control_block="c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
            ),
        ],
    ),
    BIP341ScriptPathVector(
        case_id=6,
        expected_address="bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe",
        paths=[
            ScriptPathCase(
                script="2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac",
                control_block="c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91",
            ),
            ScriptPathCase(
                script="20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac",
                control_block="c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
            ),
            ScriptPathCase(
                script="20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac",
                control_block="c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
            ),
        ],
    ),
]


def run_bip341_script_path_vectors() -> tuple[int, int, list[str]]:
    passed = 0
    total = 0
    details: list[str] = []
    for vector in SCRIPT_PATH_VECTORS:
        for idx, case in enumerate(vector.paths):
            total += 1
            try:
                result = analyze_taproot(
                    control_block=case.control_block,
                    script=case.script,
                    network="mainnet",
                    expected_address=vector.expected_address,
                )
                ok = bool(result.checks.expectedAddressMatch)
            except AnalysisError as exc:
                ok = False
                details.append(f"case#{vector.case_id} path#{idx}: {exc.code}: {exc.message}")
            if ok:
                passed += 1
            else:
                details.append(f"case#{vector.case_id} path#{idx}: expectedAddressMatch=false")
    return passed, total, details
