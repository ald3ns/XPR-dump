private rule mach_magic
{
    condition:
        uint32(0) == 0xfeedface
        or uint32(0) == 0xcefaedfe
}

private rule mach64_magic
{
    condition:
        uint32(0) == 0xfeedfacf
        or uint32(0) == 0xcffaedfe
}

private rule fat_mach_magic
{
    condition:
        uint32(0) == 0xcafebabe
        or uint32(0) == 0xbebafeca
}

private rule fat_mach64_magic
{
    condition:
        uint32(0) == 0xcafebabf
        or uint32(0) == 0xbfbafeca
}

private rule Macho
{
    condition:
        mach_magic
        or mach64_magic
        or fat_mach_magic
        or fat_mach64_magic
}

rule multi_snowdrift {
    strings:
        $snowdrift_pcloud_object = /\/MainTask\/BaD\/.{10,100}\/pCloud.o/
        $pcloud = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
        $manage_cloud = "-[Management initCloud:access_token:]"
        $globs = "*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.hwp;*.hwpx;*.csv;*.pdf;*.rtf;*.amr;*.3gp;*.m4a;*.txt;*.mp3;*.jpg;*.eml;*.emlx"
    condition:
        Macho and 2 of them
}