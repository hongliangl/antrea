// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import "sort"

var pipelineCache = make(map[PipelineID]*ofPipeline)

type ofPipeline struct {
	pipelineID PipelineID
	tableMap   map[StageID][]Table
	firstTable Table
	lastTable  Table
	firstStage StageID
	lastStage  StageID
}

func (p *ofPipeline) GetFirstTableInStage(id StageID) Table {
	tables, ok := p.tableMap[id]
	if ok {
		return tables[0]
	}
	return nil
}

func (p *ofPipeline) ListTablesInStage(id StageID) []Table {
	return p.tableMap[id]
}

func (p *ofPipeline) IsStageValid(stage StageID) bool {
	_, ok := p.tableMap[stage]
	return ok
}

func (p *ofPipeline) GetFirstTable() Table {
	return p.firstTable
}

func (p *ofPipeline) IsLastTable(t Table) bool {
	return t.GetID() == p.lastTable.GetID()
}

func (p *ofPipeline) ListAllTables() []Table {
	tables := make([]Table, 0)
	for _, t := range p.tableMap {
		tables = append(tables, t...)
	}
	sort.Slice(tables, func(i, j int) bool {
		return tables[i].GetID() < tables[j].GetID()
	})
	return tables
}

func NewPipeline(id PipelineID, ofTables []Table) Pipeline {
	tableMap := make(map[StageID][]Table)
	for _, t := range ofTables {
		tableMap[t.GetStageID()] = append(tableMap[t.GetStageID()], t)
	}
	p := &ofPipeline{pipelineID: id, tableMap: tableMap}

	for s := FirstStage; s <= LastStage; s++ {
		if tables, ok := tableMap[s]; ok {
			p.firstStage = s
			p.firstTable = tables[0]
			break
		}
	}
	for s := LastStage; true; s-- {
		if tables, ok := tableMap[s]; ok {
			p.lastStage = s
			tableCount := len(tables)
			p.lastTable = tables[tableCount-1]
			break
		}
	}
	pipelineCache[id] = p
	return p
}
