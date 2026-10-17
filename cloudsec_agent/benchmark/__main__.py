import argparse
import json
from pathlib import Path

from .analysis import aggregate
from .artifacts import ArtifactStore, atomic_json
from .m8d import DEFAULT_ROOT, digest, load_spec, schedule, structural_preflight


def main():
    parser = argparse.ArgumentParser(description='M8D offline preparation and aggregation only')
    parser.add_argument('command', choices=['inspect', 'prepare', 'aggregate'])
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    spec = load_spec()
    if args.command == 'inspect':
        print(json.dumps({'spec_digest': digest(spec),
                          'treatment_digest': digest(spec['treatment']),
                          'scheduler_digest': digest(schedule(spec)),
                          'runs': len(schedule(spec)),
                          'preflight': structural_preflight(spec)}, indent=2))
        return
    store = ArtifactStore(args.root)
    if args.command == 'prepare':
        print(json.dumps(store.initialize(spec), indent=2))
    else:
        with store.locked():
            result = aggregate(spec, store.records())
            path = store.root / 'aggregates' / (digest(result) + '.json')
            if not path.exists():
                atomic_json(path, result)
            print(path)


if __name__ == '__main__':
    main()
