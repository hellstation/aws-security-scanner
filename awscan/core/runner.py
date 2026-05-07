from concurrent.futures import ThreadPoolExecutor, as_completed

def run_checks_parallel(checks, session):
    results = []

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(check, session) for check in checks]

        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as e:
                results.append({
                    "type": "ERROR",
                    "resource": "system",
                    "severity": "MEDIUM",
                    "cis": "N/A",
                    "message": str(e),
                    "evidence": "A scan module raised an exception, reducing scan coverage.",
                    "confidence": 1.0,
                })

    return results
