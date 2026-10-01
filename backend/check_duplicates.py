"""
Duplicate-detection report for the phishing training dataset (CEAS_08).

Why this matters for model quality, not just data hygiene: if the same
email text appears multiple times in the dataset -- especially with
conflicting labels (once marked phishing, once marked legitimate) --
it can leak between train/test splits (the model "memorizes" an exact
duplicate instead of generalizing) and inflate reported accuracy
without reflecting real-world performance. This script quantifies the
problem before any training happens, and optionally writes a cleaned,
deduplicated copy.
"""

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

_REQUIRED_COLUMNS = {"subject", "body"}


def build_email_text(df: pd.DataFrame) -> pd.Series:
    """
    Builds the combined text field used for both duplicate detection
    and downstream TF-IDF vectorization -- kept as a single source of
    truth so the definition of "duplicate" here matches exactly what
    the model actually sees as input, not some looser approximation.
    """
    subject = df["subject"].fillna("").astype(str).str.strip()
    body = df["body"].fillna("").astype(str).str.strip()
    return "Subject: " + subject + "\n" + body


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        logger.error("Dataset file not found: %s", path)
        sys.exit(1)

    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        logger.error("Dataset file is empty: %s", path)
        sys.exit(1)
    except pd.errors.ParserError as e:
        logger.error("Failed to parse CSV %s: %s", path, e)
        sys.exit(1)

    missing = _REQUIRED_COLUMNS - set(df.columns)
    if missing:
        logger.error(
            "Dataset is missing required column(s): %s (found: %s)",
            sorted(missing), sorted(df.columns),
        )
        sys.exit(1)

    return df


def report_duplicates(df: pd.DataFrame, label_column: str | None) -> dict:
    """
    Computes duplicate statistics. If label_column is present and
    exists in df, also reports "conflicting duplicates" -- the same
    exact email text appearing under two different labels, which is a
    more serious data-quality problem than a plain repeated email
    (it's actively contradictory training signal, not just redundant).
    """
    total = len(df)
    duplicated_mask = df["email_text"].duplicated(keep=False)  # keep=False
    # flags ALL rows involved in a duplicate group, not just the 2nd+
    # occurrence -- more useful for actually inspecting what's
    # duplicated, vs. the original's .duplicated() (default keep="first")
    # which only counts the redundant copies.

    total_duplicate_rows = int(duplicated_mask.sum())
    duplicate_groups = int(df.loc[duplicated_mask, "email_text"].nunique())
    unique_texts = int(df["email_text"].nunique())

    stats = {
        "total_emails": total,
        "unique_emails": unique_texts,
        "rows_involved_in_duplicates": total_duplicate_rows,
        "distinct_duplicate_groups": duplicate_groups,
        "redundant_rows_removable": total - unique_texts,
    }

    if label_column and label_column in df.columns:
        conflicting_groups = (
            df.groupby("email_text")[label_column]
            .nunique()
            .gt(1)
            .sum()
        )
        stats["conflicting_label_duplicate_groups"] = int(conflicting_groups)
    else:
        stats["conflicting_label_duplicate_groups"] = None
        if label_column:
            logger.warning(
                "label_column '%s' not found in dataset; skipping label-conflict check",
                label_column,
            )

    return stats


def print_report(stats: dict) -> None:
    print("--- DUPLICATE CHECK ---")
    print(f"Total emails:                     {stats['total_emails']}")
    print(f"Unique emails:                    {stats['unique_emails']}")
    print(f"Rows involved in duplicate groups: {stats['rows_involved_in_duplicates']}")
    print(f"Distinct duplicate groups:         {stats['distinct_duplicate_groups']}")
    print(f"Redundant rows (removable):        {stats['redundant_rows_removable']}")

    if stats["conflicting_label_duplicate_groups"] is not None:
        conflicts = stats["conflicting_label_duplicate_groups"]
        print(f"Duplicate groups with conflicting labels: {conflicts}")
        if conflicts > 0:
            print(
                f"  ⚠ WARNING: {conflicts} email text(s) appear under more than one "
                "label. This is contradictory training signal and should be "
                "resolved (e.g. drop, or trust one label source) before training."
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report and optionally remove duplicate emails in the training dataset."
    )
    parser.add_argument(
        "--input", type=Path, default=Path("data/CEAS_08.csv"),
        help="Path to the input CSV (default: data/CEAS_08.csv)",
    )
    parser.add_argument(
        "--label-column", type=str, default="label",
        help="Column name containing the phishing/legitimate label, used to "
             "detect conflicting duplicates (default: 'label'; set to '' to skip)",
    )
    parser.add_argument(
        "--dedup-output", type=Path, default=None,
        help="If provided, writes a deduplicated copy of the dataset to this path "
             "(keeps the first occurrence of each duplicate group).",
    )
    args = parser.parse_args()

    df = load_dataset(args.input)
    df["email_text"] = build_email_text(df)

    label_column = args.label_column or None
    stats = report_duplicates(df, label_column)
    print_report(stats)

    if args.dedup_output:
        deduped = df.drop_duplicates(subset="email_text", keep="first")
        args.dedup_output.parent.mkdir(parents=True, exist_ok=True)
        deduped.drop(columns=["email_text"]).to_csv(args.dedup_output, index=False)
        logger.info(
            "Wrote deduplicated dataset (%d rows, was %d) to %s",
            len(deduped), len(df), args.dedup_output,
        )


if __name__ == "__main__":
    main()