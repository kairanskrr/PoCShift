# Condition Translation


This folder contains files for mining implicitly required state variables and their values from the extracted exploit logic based on event analysis and condition translation:

#### `event_count_detail.json`

Stores detailed event information, including parameter names, types, and values, for all observed events.

#### `event_count.csv`

Provides statistics for event frequency by event name.

#### `translation_pipeline.json`

Contains two main sections:
* `event_property_mapping_table`: converts raw event logs into structured properties.
* `condition_translation_logic`: defines how structured properties are translated into VM operations. The code version can be found in `condition_translation.py`.

