WORKLOADS = [
    ("simple_research", "solo", [
        "What is the boiling point of water at sea level in Celsius?",
        "Who wrote the novel Dune?",
        "What year was the Python programming language first released?",
        "What is the capital of Australia?",
        "What is the speed of light in a vacuum, in km/s?",
        "Who is the current Secretary-General of the United Nations?",
    ]),
    ("multi_step_research", "solo", [
        "Find the population of Japan and compare it to the population of Germany.",
        "Find the release year of the first iPhone and the release year of the first Android phone, then state which came first.",
        "Find who directed the movie Inception and list two other movies by the same director.",
        "Find the tallest mountain in Africa and its height in meters.",
        "Find the founding year of NASA and the founding year of ESA.",
        "Find the author of 'A Brief History of Time' and one other book by them.",
    ]),
    ("technology_comparison", "manager_1", [
        "Compare Python and Rust for systems programming, briefly.",
        "Compare REST and GraphQL for API design, briefly.",
        "Compare SQL and NoSQL databases, briefly.",
        "Compare TCP and UDP, briefly.",
        "Compare Docker and virtual machines, briefly.",
        "Compare React and Vue.js, briefly.",
    ]),
    ("document_technical_analysis", "manager_1", [
        "Summarize what OAuth 2.0 scope containment means.",
        "Summarize how DNS resolution works at a high level.",
        "Summarize what a Bloom filter is used for.",
        "Summarize the CAP theorem in distributed systems.",
        "Summarize what a Merkle tree is used for.",
        "Summarize what a garbage collector does in a runtime.",
    ]),
    ("manager_specialist_delegation", "manager_1", [
        "Find the current version of the Rust programming language.",
        "Find the current stable version of PostgreSQL.",
        "Find the latest LTS version of Node.js.",
        "Find the most recent version of the Kubernetes API.",
        "Find the current version of the TypeScript language.",
        "Find the latest major version of the Linux kernel.",
    ]),
    ("manager_multi_specialist", "manager_2", [
        "Find the current population of France, then compute what 10 percent of it is.",
        "Find the current price of one troy ounce of gold in USD, then compute the cost of 3 ounces.",
        "Find the distance from Earth to the Moon in kilometers, then compute how many hours light takes to cover it.",
        "Find the number of countries in the European Union, then compute how many pairs of countries that allows.",
        "Find the current world record for the marathon, then compute the average pace per kilometer.",
        "Find the height of the Eiffel Tower in meters, then compute its height in feet.",
    ]),
    # v2 cell A (depth axis, docs/collection-plan-v2.md): same wording as
    # manager_specialist_delegation, chained_2 topology forces the 2-hop.
    ("manager_specialist_delegation_chained_2", "chained_2", [
        "Find the current version of the Rust programming language.",
        "Find the current stable version of PostgreSQL.",
        "Find the latest LTS version of Node.js.",
        "Find the most recent version of the Kubernetes API.",
        "Find the current version of the TypeScript language.",
        "Find the latest major version of the Linux kernel.",
    ]),
    # v2 cell B (fanout axis): forced_multi_lookup family, new per
    # docs/collection-plan-v2.md's "look up X, look up Y, then combine" spec.
    ("forced_multi_lookup", "manager_4", [
        "Look up the height of Mount Kilimanjaro in meters, then convert that height into feet, "
        "then look up the height of Mount Fuji in meters, then compute the difference between the "
        "two heights in meters.",
        "Look up the current population of Brazil, then look up the current population of "
        "Argentina, then compute the combined population of both countries.",
        "Look up the boiling point of water in Celsius at sea level, then convert that temperature "
        "into Fahrenheit, then look up the freezing point of water in Celsius, then compute the "
        "difference between the boiling and freezing points in Celsius.",
        "Look up the length of the Amazon River in kilometers, then convert that length into "
        "miles, then look up the length of the Nile River in kilometers, then compute which river "
        "is longer and by how many kilometers.",
        "Look up the current price of one barrel of crude oil in USD, then look up the current "
        "exchange rate from USD to EUR, then compute the price of one barrel in EUR.",
        "Look up the wingspan of a Boeing 747 in meters, then convert it into feet, then look up "
        "the wingspan of an Airbus A380 in meters, then compute the difference between the two "
        "wingspans in meters.",
    ]),
]
