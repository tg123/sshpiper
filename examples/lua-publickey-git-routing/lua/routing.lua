function sshpiper_on_publickey(conn, key)
    if conn.sshpiper_user == "repo-a" then
        return {
            host = "git-a:22",
            username = "git",
            private_key_data = [[-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCBLQ9D/0LORmbOF3j3nhBBQZiy+q4AL5A7Z/zm6LZjggAAAJg+xj1NPsY9
TQAAAAtzc2gtZWQyNTUxOQAAACCBLQ9D/0LORmbOF3j3nhBBQZiy+q4AL5A7Z/zm6LZjgg
AAAECHpreevsShLARdtRiRIBE5ggpG2B7cR1Mv44YL1fMWZoEtD0P/Qs5GZs4XePeeEEFB
mLL6rgAvkDtn/ObotmOCAAAAFHJ1bm5lckBydW5uZXJ2bXdmZno0AQ==
-----END OPENSSH PRIVATE KEY-----]],
            ignore_hostkey = true
        }
    end

    if conn.sshpiper_user == "repo-b" then
        return {
            host = "git-b:22",
            username = "git",
            private_key_data = [[-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAO6lfzR2AxBC4GLuVQvfQU0kIm7TgPjI9e2Arx9GxGAgAAAJgjLgURIy4F
EQAAAAtzc2gtZWQyNTUxOQAAACAO6lfzR2AxBC4GLuVQvfQU0kIm7TgPjI9e2Arx9GxGAg
AAAEBrHfZaZMdjBg54Q8nuzD51n4hl/0m3Sm2At3z8iw662g7qV/NHYDEELgYu5VC99BTS
QibtOA+Mj17YCvH0bEYCAAAAFHJ1bm5lckBydW5uZXJ2bXdmZno0AQ==
-----END OPENSSH PRIVATE KEY-----]],
            ignore_hostkey = true
        }
    end

    return nil
end
