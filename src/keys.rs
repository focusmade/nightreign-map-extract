/// Nightreign RSA public keys for BHD5 archive decryption.
/// PKCS#1 format (RSA PUBLIC KEY). Verified from Smithbox and DantelionDataManager.

pub struct ArchiveKey {
    pub name: &'static str,
    pub bhd_path: &'static str,
    pub bdt_path: &'static str,
    pub pem: &'static str,
}

pub const ARCHIVES: &[ArchiveKey] = &[
    ArchiveKey {
        name: "data0",
        bhd_path: "data0.bhd",
        bdt_path: "data0.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBDAKCAQEAz8F9U1V9hgKs40gdzl1ZOf3IBirf6xUEzXtDd6oSEBE6XiYocvAB\n\
ykiK+WMdAaJL7HJ58Gt2xSRxA3t9toCGKMI/3gNAfcR0BV83gsQo0O0dVP0fqyxX\n\
lA2pGN5B4IE8aLWPX2cNNFSFKAdjYnzsYSevzef/pgnpV1ZgPf2j2SQwNGSufYeN\n\
3Owji8l0K2C0fKIx6gSO0cK9kvTIm8AdpvzZbBkTylT1jF3m8DsSA1OFzFJTdFyZ\n\
bTRi85M6bmv6rHtvZc5OW21dye7Q6fmLlxOyMetLTu4dpOXjHAAf/LFTbfQpXFr9\n\
aXO4O6I7nWDJn7FRzNlLkb8RwSyZ1/KWyQIFALEDsAc=\n\
-----END RSA PUBLIC KEY-----",
    },
    ArchiveKey {
        name: "data1",
        bhd_path: "data1.bhd",
        bdt_path: "data1.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBDAKCAQEA0E6dtnDmT6d2+VaNkPzomUNv+T6896H//RAaTR2guPACMDNZpAsF\n\
vV3MfNcR2BS6Cbxl55MmMWsmsZs1s293MuOdS+c99vmZbNYcXWjx0uJGO+VrRXe4\n\
3TRzmQFh1uD+Xcq6+wYfTrGyLOdAtmwdDXNvW8jYoFDM7nsuoPKOXKtKd0uz7/MK\n\
ZYLk1J7pAoBQqw9VD5qi2Ih86zn0VWm5lLMTI0qnutOzpZVDvZWBg/jr4Nbnr/Ox\n\
PLeJO1tFuRuHUPuBAWtYM/J23MPqqKkQrG5z2r7PexUI744UPdmo3Sn+Mqynuxxv\n\
V9SEhska6pStzn8R9i94wOKPTQ32HEFuUQIFAP////8=\n\
-----END RSA PUBLIC KEY-----",
    },
    ArchiveKey {
        name: "data2",
        bhd_path: "data2.bhd",
        bdt_path: "data2.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBDAKCAQEAqpkf9yHnx8k84+WXITLFUW/STypXjZMPuw842pzNHa5L7v9gU4M5\n\
hBHwTQs0YIcfnf+mbjqoJYnmYPBblxLjFXgwT4ICJdpnPMY75BwD0Nv28/CvvIsA\n\
0QQWOhUeOXnm5BT26dGYi3CHHPvD14F76tJt3TO/CC3fyhdxne9Cra5G87aGTJGv\n\
0ImsU0KPCizYX/RHQ2jdJdlB5BHzkMgLhIaEdhC3nhIqMJDNQNGKMo7rRV1tAEGf\n\
0zIZ23PGEsPsbVg31nnnRoq338WfD9ArZZG6bM11vlfVcYmrJs7v4vBjKXnYVwVX\n\
0rQGIfSNDnaZcEj4tsl04AqnupTdvSrHXwIFANOg6RU=\n\
-----END RSA PUBLIC KEY-----",
    },
    ArchiveKey {
        name: "data3",
        bhd_path: "data3.bhd",
        bdt_path: "data3.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCwKCAQEAwm2Rcw4eoP8FgWijxw1X8b9rEVFsVqy7rXWcH2yVm61yYBlzPlTq\n\
Kqnc2VeqZSh/TLXeFY3+Om2X78RQxZNS3L3OokvD7l/0wqPIpXSSumeeL8UAZm5k\n\
7nFA2m2HJfc+F07kNwwCEqhmFs5YQIMnWyIrqnEax/qSncFErLjIYMBMArVnVLE8\n\
WqgsD7N8lW937dlUcT2TaPh1HfjavKOSUy/OHM9zaneyDL4NRmDdU8GmNXTSm5kP\n\
YoSRCDIvFVj0g5iaXr60eRh0d+40TctoBUdtaoJCPOyRlmkE7qU6Q9FyyvMNbhtf\n\
D95d+6IJejNd7kvyV/ISlB37kb2Uh9TavwIEOqKLtw==\n\
-----END RSA PUBLIC KEY-----",
    },
    ArchiveKey {
        name: "dlc01",
        bhd_path: "dlc01.bhd",
        bdt_path: "dlc01.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBDAKCAQEA1q4MOehlD++h5Ietq9Jk97eGOJL2zDpDcu9Wk6RXK1+R3LycMBQl\n\
L/hnPg/qqvcoViA7wLX5GOFr5lo6dtKaQqlBkBqgYHGIdBvioBPZ8BuXAjYr3sm8\n\
N0SYC2TNHXmfw6yFC+ePsrl+gNldrO//XXY27hsGgcegfWr6JuQaJti/BOKlGb8A\n\
RbKwyIqGc5WiWj/v0tGE1cdPi0fLQRbTrLFaQtx1roQVqsQuJ5zRGTpnj/mhaJtq\n\
J7V0s5gLG5CCevx71lN8m7oyWk2JemzSLvllwv4tjtzrw3jNQtiYb8nzy2Spjibs\n\
vX1iRCg5btMSiNPcSeIJ5jX+FUW9LSnrkwIFAKhopbM=\n\
-----END RSA PUBLIC KEY-----",
    },
    ArchiveKey {
        name: "sd",
        bhd_path: "sd/sd.bhd",
        bdt_path: "sd/sd.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCwKCAQEA19Y/R69SXASLOgInwfAXjAXuWSTQ6GP7XNoMDY0ThefISGG2p7G5\n\
oQDpvK9oMGISCqHTr4ijs31GoC0dBG5Vnl1dRO+teXORoy+vlM3dRc1XyBXWkLM8\n\
8O8PkhWeisf2EGyAa1jGjAAPNblKIAWbUFsxW2Ve7PKRF3FQAIiSPiOIbc24C3zE\n\
TpbKDCVoDlm80DTv+Fg2ZdgD985ZDGtwBvg+RRe19iLg7imcrHeZdvqI/CzaY+r3\n\
l5hFle31jjWopOm8sORZUMAWPFxuGm+lnB7v0iCCTboq+YC24sOXNabjsgnKkQF1\n\
1G7uQz1qjnmQxnp3FgbnHRe1I3mCwELuvwIEOC192w==\n\
-----END RSA PUBLIC KEY-----",
    },
    ArchiveKey {
        name: "sd_dlc01",
        bhd_path: "sd/sd_dlc01.bhd",
        bdt_path: "sd/sd_dlc01.bdt",
        pem: "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCwKCAQEA19Y/R69SXASLOgInwfAXjAXuWSTQ6GP7XNoMDY0ThefISGG2p7G5\n\
oQDpvK9oMGISCqHTr4ijs31GoC0dBG5Vnl1dRO+teXORoy+vlM3dRc1XyBXWkLM8\n\
8O8PkhWeisf2EGyAa1jGjAAPNblKIAWbUFsxW2Ve7PKRF3FQAIiSPiOIbc24C3zE\n\
TpbKDCVoDlm80DTv+Fg2ZdgD985ZDGtwBvg+RRe19iLg7imcrHeZdvqI/CzaY+r3\n\
l5hFle31jjWopOm8sORZUMAWPFxuGm+lnB7v0iCCTboq+YC24sOXNabjsgnKkQF1\n\
1G7uQz1qjnmQxnp3FgbnHRe1I3mCwELuvwIEOC192w==\n\
-----END RSA PUBLIC KEY-----",
    },
];
