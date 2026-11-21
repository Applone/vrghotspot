struct SignatureSet {
    build: &'static str,
    hash: &'static str,
    methods: &'static [(&'static str, &'static str)],
}

const SIGNATURE_SETS: &[SignatureSet] = &[
    SignatureSet {
        build: "Windows 11 reference",
        hash: "1bdccc9dabadbf372bf1a81f42aab8a4bdb48a221d816d48352b94a624f71794",
        methods: WINDOWS_11,
    },
    SignatureSet {
        build: "Windows 10 10.0.19041.4355",
        hash: "275b3bd71a918582169d3738ccf0816150c4e33e2bb492eb53d3157f769c2499",
        methods: WINDOWS_10,
    },
];

const GET_GUID: &str = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 48 8B FA 48 8B D9 48 8B 0D ? ? ? ? 48 8D 2D ? ? ? ? 4C 8D 35 ? ? ? ? 48 3B CD 74 ? F6 41 ? ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? BA 33 00 00 00 4D 8B C6 E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 85 FF 75 ? BB 03 40 00 80";
const REMOVE_PUBLIC: &str = "48 89 5C 24 ? 48 89 74 24 ? 41 54 41 55 41 56 48 83 EC 40 48 8B F1 48 8B 0D ? ? ? ? 4C 8D 25 ? ? ? ? 4C 8D 2D ? ? ? ? 49 3B CC 74 ? F6 41 ? ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? BA 0A 00 00 00 4D 8B C5 E8 ? ? ? ? 48 83 64 24 ? ? 4C 8D 76 ? 49 8B CE BA 32 00 00 00";

// Byte signatures preserved from the reviewed PowerShell implementation.
const WINDOWS_11: &[(&str, &str)] = &[
    ("SharePublic", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC 80 02 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B F2 48 8B F9 48 8B 0D ? ? ? ? 4C 8D 2D ? ? ? ? 41 B4 08 49 3B CD 74 ? 44 84 61 ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? 4C 8D 05"),
    ("SharePrivate", "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 55 41 56 48 8B EC 48 83 EC 70 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 4C 8B F2 48 8B F9 48 8B 0D ? ? ? ? 48 8D 35 ? ? ? ? 41 B5 08 48 3B CE 74 ? 44 84 69 ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? 4C 8D 05 ? ? ? ? BA 84 00 00 00 E8"),
    ("DisableIcs", "40 55 53 56 57 41 55 41 56 41 57 48 8B EC 48 83 EC 40 4D 8B F0 48 8B FA 48 8B F1 48 8B 0D ? ? ? ? 4C 8D 2D ? ? ? ? 49 3B CD 74 ? F6 41 ? ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? 4C 8D 05 ? ? ? ? BA 9F 00 00 00 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 FF 4C 89 7D ? 41 8B DF"),
    ("GetIHNetConnectionForGuid", "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 55 41 56 41 57 48 8B EC 48 83 EC 30 45 8A F9 48 8B FA 4C 8B F1 48 8B 0D ? ? ? ? 48 8D 35 ? ? ? ? 41 B5 08 48 3B CE 74 ? 44 84 69 ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? 4C 8D 05 ? ? ? ? BA 23 00 00 00 E8 ? ? ? ? 48 8B 0D"),
    ("GetGuid", GET_GUID),
    ("RemovePrivate", "48 89 5C 24 ? 48 89 74 24 ? 57 41 54 41 57 48 83 EC 40 48 8B F1 48 8B 0D ? ? ? ? 4C 8D 3D ? ? ? ? 4C 8D 25 ? ? ? ? 49 3B CF 74 ? F6 41 ? ? 74 ? 80 79 ? ? 72 ? 48 8B 49 ? BA 0A 00 00 00 4D 8B C4 E8 ? ? ? ? 48 83 64 24 ? ? 48 8D BE ? ? ? ? 48 8B CF BA 32 00 00 00"),
    ("RemovePublic", REMOVE_PUBLIC),
];

// The COM vtables in this build point directly to these seven entries.
const WINDOWS_10: &[(&str, &str)] = &[
    ("SharePublic", "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 70 FE FF FF 48 81 EC 90 02 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 80 01 00 00 4C 8B F2 48 8B F9 48 8B 0D ? ? ? ? 4C 8D 2D ? ? ? ? 41 B4 08 49 3B CD 74 ? 44 84 61 1C 74 ? 80 79 19 06 72 ? 48 8B 49 10 4C 8D 05 ? ? ? ? BA 75 00 00 00"),
    ("SharePrivate", "48 89 5C 24 18 48 89 74 24 20 55 57 41 54 41 55 41 56 48 8B EC 48 83 EC 70 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 F0 4C 8B F2 48 8B F9 48 8B 0D ? ? ? ? 48 8D 35 ? ? ? ? 41 B4 08 48 3B CE 74 ? 44 84 61 1C 74 ? 80 79 19 06 72 ? 48 8B 49 10 4C 8D 05 ? ? ? ? BA 84 00 00 00 E8"),
    ("DisableIcs", "40 55 53 56 57 41 55 41 56 41 57 48 8B EC 48 83 EC 40 4D 8B F0 48 8B F2 48 8B F9 48 8B 0D ? ? ? ? 4C 8D 2D ? ? ? ? 49 3B CD 74 ? F6 41 1C 08 74 ? 80 79 19 06 72 ? 48 8B 49 10 4C 8D 05 ? ? ? ? BA 9F 00 00 00 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 FF 4C 89 7D F8 41 8B DF"),
    ("GetIHNetConnectionForGuid", "48 89 5C 24 10 48 89 74 24 18 4C 89 64 24 20 55 41 56 41 57 48 8B EC 48 83 EC 30 45 8A E1 48 8B F2 4C 8B F1 48 8B 0D ? ? ? ? 4C 8D 3D ? ? ? ? 49 3B CF 74 ? F6 41 1C 08 74 ? 80 79 19 06 72 ? 48 8B 49 10 4C 8D 05 ? ? ? ? BA 23 00 00 00 E8 ? ? ? ? 48 8B 0D"),
    ("GetGuid", GET_GUID),
    ("RemovePrivate", "48 89 5C 24 18 48 89 6C 24 20 56 41 54 41 55 48 83 EC 40 48 8B E9 48 8B 0D ? ? ? ? 4C 8D 25 ? ? ? ? 4C 8D 2D ? ? ? ? 49 3B CC 74 ? F6 41 1C 08 74 ? 80 79 19 06 72 ? 48 8B 49 10 BA 0A 00 00 00 4D 8B C5 E8 ? ? ? ? 48 83 64 24 60 00 48 8D B5 68 FF FF FF 48 8B CE BA 32 00 00 00"),
    ("RemovePublic", REMOVE_PUBLIC),
];
