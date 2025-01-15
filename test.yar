rule YaraTest
{

    meta:
        author = "cccs-rs"

    strings:
        $yara = "Yara"

    condition:
        $yara
}
