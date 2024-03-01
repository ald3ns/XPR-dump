rule MACOS_CRAPYRATOR_S1
{
    strings:
        $ = {
            69 6d 70 6f 72 74 20 73 75 62 70 72 6f 63 65 73 73
            [1-6] 69 6d 70 6f 72 74 20 74 69 6d 65
            [1-10] 77 68 69 6c 65 20 54 72 75 65 3a
            [1-10] 73 75 62 70 72 6f 63 65 73 73 2e 63 61 6c 6c 28 5b 27 6b 69 6c 6c 61 6c 6c 27 2c 20 27 4e 6f 74 69 66 69 63 61 74 69 6f 6e 43 65 6e 74 65 72 27 5d 29
            [1-10] 74 69 6d 65 2e 73 6c 65 65 70 28 [1-5] 29
        }

    condition:
        any of them and filesize < 10KB
}

rule MACOS_CRAPYRATOR_S2
{
    strings:
        $ = {
            77 68 69 6c 65 20 54 72 75 65 3a
            [2-20] 74 72 79 3a
            [2-20] 73 20 3d 20 4e 6f 6e 65
            [2-20] 77 69 74 68 20 75 72 6c 6c 69 62 2e 72 65 71 75 65 73 74 2e 75 72 6c 6f 70 65 6e 28 [10-100] 29 20 61 73 20 66 3a
            [2-20] 73 20 3d 20 66 2e 72 65 61 64 28 29
            [2-20] 77 69 74 68 20 73 75 62 70 72 6f 63 65 73 73 2e 50 6f 70 65 6e 28 5b 73 79 73 2e 65 78 65 63 75 74 61 62 6c 65 5d 2c 20 73 74 64 69 6e 3d 73 75 62 70 72 6f 63 65 73 73 2e 50 49 50 45 29 20 61 73 20 70 3a
            [2-20] 70 2e 63 6f 6d 6d 75 6e 69 63 61 74 65 28 69 6e 70 75 74 3d 73 2c 20 74 69 6d 65 6f 75 74 3d [2-6] 29 5b 30 5d
            [2-20] 70 2e 6b 69 6c 6c 28 29
            [2-20] 65 78 63 65 70 74 20 45 78 63 65 70 74 69 6f 6e 20 61 73 20 65 3a 20
            [2-20] 70 61 73 73
            [2-20] 74 69 6d 65 2e 73 6c 65 65 70 28 [1-5] 29
        }

    condition:
        any of them and filesize < 10KB
}

rule MACOS_CRAPYRATOR_S3
{
    strings:
        $ = {
            4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 43 41 33 59 6f 2b 4c 68 4e 75 69 30 41 56 6f 54 2f 76 2b 43 72 57 56 64 6c 2b [1-8]
            2f 56 62 62 6e 36 52 79 45 57 30 63 62 4d 44 4e 37 50 55 41 61 67 68 6f 76 63 57 58 47 42 4c 4c 4a 61 49 39 47 62 52 30 72 30 43 4c 46 6c 78 54 79 64 4e 5a 35 58 36 47 32 38 6d 41 52 6d 56 4f [1-8]
            4b 4f 75 38 53 64 68 67 74 64 38 63 59 35 31 6d 6b 4a 4a 46 74 6d 41 59 51 6c 64 4b 2f 4f 64 4b 30 6f 33 2b 45 6f 61 4f 30 59 30 78 73 71 78 65 49 74 55 75 67 49 36 57 7a 36 55 44 2f 35 42 34 [1-8]
            31 70 31 65 39 30 53 6a 54 78 53 6e 36 5a 69 4b 38 51 49 44 41 51 41 42
        }

    condition:
        any of them and filesize < 10KB
}

rule MACOS_CRAPYRATOR_S4
{
    strings:
        $ = { 68 74 74 70 73 3a 2f 2f 63 6c 6f 75 64 66 6c 61 72 65 2d 64 6e 73 2e 63 6f 6d 2f 64 6e 73 2d 71 75 65 72 79 3f 6e 61 6d 65 3d 7b 7d 26 74 79 70 65 3d 54 58 54 }
        $ = {
            77 69 74 68 20 73 75 62 70 72 6f 63 65 73 73 2e 50 6f 70 65 6e 28 5b 73 79 73 2e 65 78 65 63 75 74 61 62 6c 65 5d 2c 20 73 74 64 69 6e 3d 73 75 62 70 72 6f 63 65 73 73 2e 50 49 50 45 29 20 61 73 20 70 3a [2-40]
            70 2e 63 6f 6d 6d 75 6e 69 63 61 74 65 28 69 6e 70 75 74 3d [1-2] 2c 20 74 69 6d 65 6f 75 74 3d [2-6] 29 5b 30 5d [2-40]
            70 2e 6b 69 6c 6c 28 29
        }

    condition:
        all of them and filesize < 10KB
}