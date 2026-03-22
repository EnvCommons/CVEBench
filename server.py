from openreward.environments import Server

from cve_bench import CVEBench

if __name__ == "__main__":
    Server([CVEBench]).run()
