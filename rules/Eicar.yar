rule EICAR: Example Test {
    meta:
        name = "EICAR.A"
        version = 1337
        enabled = true

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        $eicar_substring
}