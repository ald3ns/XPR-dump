private rule electron_archive {
    strings:
        // Note this may be unstable, they have considered changing this in the past
        $magic = {0400 0000}
    condition:
        $magic at 0
}

rule multi_snowbeagle_backdoor {
        strings:
            $backdoor_trigger = "UpdateCheckAsync(email);" ascii wide
            $backdoor_function = "UpdateCheckSync(varemail)" ascii wide
            $backdoor_exports = "UpdateCheckSync,UpdateCheckAsync" ascii wide

            $javascript_chmod_a = /\("fs"\)\.chmodSync\(.,511\)/ ascii wide
            $javascript_chmod_b = "require('fs').chmodSync(updateExeLocalPath," ascii wide
            $javascript_chmod_c = /\.chmodSync\(.,755\)/ ascii wide

            $javascript_update_path = "/update/\"+JSON.parse(o).path;"

            $request_options = "\"),request({rejectUnauthorized:!1,url:"

            $javascript_command_a = "(\"fs\").chmodSync(o,511),setTimeout((function(){r(\"child_process\").exec(o),console.log(\"Update Finished\")" ascii wide
            $javascript_command_b = "&&(o(47).writeFileSync(s,Buffer.from(f.data,\"base64\")),o(47).chmodSync(s,755)"

            $backdoor_url_params = "var params = 'email=' + varemail + '&os=' + varos;" ascii wide
            $backdoor_url_params_a = /"email="\+.{1,3}\+"&os="\+.{1,3}/ ascii wide
            $backdoor_useragent_dafom = "'User-Agent': 'dafom'" ascii wide
            $backdoor_useragent_tokenais = "'User-Agent': 'tokenais'" ascii wide

            $backdoor_crypt_key = "key = Buffer.from(kkk.toString('ascii'), 'base64');" ascii wide
            $backdoor_exec = "require('child_process').exec(updateExeLocalPath);" ascii wide

            $windows_backslash = "var e=\"/\";\"win32\""
            $windows_path_a = "updateExeLocalPath = updateExeLocalPath + \".exe\"" ascii wide
            $windows_path_b = "\"\\\\\"==e&&(n+\".exe\")"
            $update_json = "var updateXmlPath = updatePath + 'update_' + require('os').platform() + \".json\"" ascii wide
            $update_xml = "updatePath + 'update_' + require('os').platform() + \".xml\"" ascii wide

            $exe_path_a =  "Math.random().toString(36).substring(8)" ascii wide
            $exe_path_b = "tmpDir + dirSplit + exeSuffix + Math.random().toString(36).substring(8);" ascii wide

            $decrypt = "let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(dkey)," ascii wide

            $dafom_appleid_password_a = "kvtv-ddia-fdev-dfnp" ascii wide
            $dafom_appleid_password_b = "linn-cafp-pdzj-yqvs" ascii wide
            $dafom_appleid_password_c = "nfog-lkim-asdt-raij" ascii wide

        condition:
            // We want to scan both packed and extracted app.asar files
            (electron_archive or filesize < 5MB) and
            3 of them

}

rule multi_snowbeagle_command_and_control {
    strings:
        $c2_aes_iv = "Excel&Words$2020" ascii wide
        $c2_salt = ".update(email + 'today_password')" ascii wide
        $c2_payload_key = "!@34QWer%^78TYui" ascii wide
        $c2_method = "LoginMe(email, vcode)" ascii wide

        $commented_out_a = "//UpdateCheckAsync();" ascii wide

        $element_email = "document.getElementById(\"txtuid\").value;" ascii wide
        $element_password = "document.getElementById(\"txtpwd\").value;" ascii wide

        $ipc_event_a = "ipcRenderer.send(\"onMainRun\", email);" ascii wide
        $ipc_event_b = "ipcRenderer.send(\"onMainRun\");" ascii wide

        $http_code_3301 = "res == 3301" ascii wide
        $http_code_2201 = "res == 2201" ascii wide
        $http_code_999 = "res == 999" ascii wide
        $http_code_4401 = "4401){ // User already exist" ascii wide

        $http_code_777_a = "777){ // Blocked user" ascii wide
        $http_code_777_b = " 777){  // count limited" ascii wide

        $http_code_888 = "888){ // vcode incorrect" ascii wide

        $http_code_555 = "555){ // need activation" ascii wide
        $need_activation_message = "You should be allowed to use this version by admin." ascii wide

        $http_code_202 = "202){ //\"Login Successful !\"){" ascii wide

        $case_28 = "throw t.prev = 28, t.t0 = t[\"catch\"](11), new Error(\"FETCH status : \" + t.t0.message);"
        $status_837593 = "837593" fullword ascii
        $status_2834673 = "2834673" fullword ascii
        $executable_name = "/utvl\""
        $webpack_hash = "1da71b65defa100813f4"
    condition:
        // We want to scan both packed and extracted app.asar files
        (electron_archive or filesize < 5MB) and
        3 of them

}

rule multi_snowbeagle_urls {
    strings:
        $url_login = /https:\/\/.{5,30}\/oauth\/login.php/ ascii wide
        $url_confirm = /https:\/\/.{5,30}\/oauth\/confirm.php/ ascii wide
        $url_signup = /https:\/\/.{5,30}\/oauth\/signup.php/ ascii wide

        $url_checkupdate = /https:\/\/.{5,30}\/oauth\/checkupdate.php/ ascii wide
        $url_loginme = /https:\/\/.{5,30}\/oauth\/loginme.php/ ascii wide
    condition:
        (electron_archive or filesize < 5MB) and
        ($url_checkupdate or 3 of them) // The checkupdate URL is super weird and has appeared on its own
}