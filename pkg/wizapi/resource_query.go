package wizapi

import (
	"encoding/json"
	"fmt"
)

// Define your GraphQL query as a constant
const ResourceQuery = `
query GraphSearch($query: GraphEntityQueryInput, $controlId: ID, $projectId: String!, $first: Int, $after: String, $fetchTotalCount: Boolean!, $quick: Boolean = true, $fetchPublicExposurePaths: Boolean = false, $fetchInternalExposurePaths: Boolean = false, $fetchIssueAnalytics: Boolean = false, $fetchLateralMovement: Boolean = false, $fetchKubernetes: Boolean = false) {
	graphSearch(
	  query: $query
	  controlId: $controlId
	  projectId: $projectId
	  first: $first
	  after: $after
	  quick: $quick
	) {
	  totalCount @include(if: $fetchTotalCount)
	  maxCountReached @include(if: $fetchTotalCount)
	  pageInfo {
		endCursor
		hasNextPage
	  }
	  nodes {
		entities {
		  ...PathGraphEntityFragment
		  userMetadata {
			isInWatchlist
			isIgnored
			note
		  }
		  technologies {
			id
			icon
		  }
		  publicExposures(first: 10) @include(if: $fetchPublicExposurePaths) {
			nodes {
			  ...NetworkExposureFragment
			}
		  }
		  otherSubscriptionExposures(first: 10) @include(if: $fetchInternalExposurePaths) {
			nodes {
			  ...NetworkExposureFragment
			}
		  }
		  otherVnetExposures(first: 10) @include(if: $fetchInternalExposurePaths) {
			nodes {
			  ...NetworkExposureFragment
			}
		  }
		  lateralMovementPaths(first: 10) @include(if: $fetchLateralMovement) {
			nodes {
			  id
			  pathEntities {
				entity {
				  ...PathGraphEntityFragment
				}
			  }
			}
		  }
		  kubernetesPaths(first: 10) @include(if: $fetchKubernetes) {
			nodes {
			  id
			  path {
				...PathGraphEntityFragment
			  }
			}
		  }
		}
		aggregateCount
	  }
	}
  }
  
	  fragment PathGraphEntityFragment on GraphEntity {
	id
	name
	type
	properties
	issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $fetchIssueAnalytics) {
	  highSeverityCount
	  criticalSeverityCount
	}
  }
  
	  fragment NetworkExposureFragment on NetworkExposure {
	id
	portRange
	sourceIpRange
	destinationIpRange
	path {
	  ...PathGraphEntityFragment
	}
	applicationEndpoints {
	  ...PathGraphEntityFragment
	}
  }
`

func resourceCreateQueryVariables(scanCloudType, scanProviderID string) map[string]interface{} {
	return map[string]interface{}{
		"quick": true,
		"first": 50,
		"query": map[string]interface{}{
			"type":   []string{"VIRTUAL_MACHINE"},
			"select": true,
			"where": map[string]interface{}{
				"cloudPlatform": map[string]interface{}{
					"EQUALS": []string{scanCloudType},
				},
				"externalId": map[string]interface{}{
					"EQUALS": []string{scanProviderID},
				},
			},
		},
		"projectId":       "*",
		"fetchTotalCount": true,
	}
}

func (w *WizAPI) graphResourceSearch(scanCloudType, scanProviderID string) (*GraphQLResourceResponse, error) {
	queryVariables := resourceCreateQueryVariables(scanCloudType, scanProviderID)
	query := ResourceQuery // GraphQL query

	response, err := w.QueryWithRetry(query, queryVariables)
	if err != nil {
		return nil, fmt.Errorf("error querying with retry: %w", err)
	}

	// Process the HTTP response and unmarshal the JSON into GraphQLResourceResponse
	var graphQLResourceResponse GraphQLResourceResponse
	if err := json.NewDecoder(response.Body).Decode(&graphQLResourceResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	if len(graphQLResourceResponse.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", graphQLResourceResponse.Errors)
	}

	return &graphQLResourceResponse, nil
}

// GetResourceID executes the GraphQL query and returns the matched resource ID.
func (w *WizAPI) GetResourceID(cloudType, providerID string) (string, error) {
	graphQLResourceResponse, err := w.graphResourceSearch(cloudType, providerID)
	if err != nil {
		return "", fmt.Errorf("error executing GraphResourceSearch: %w", err)
	}
	if graphQLResourceResponse.Data.GraphSearch.TotalCount != 1 {
		return "", fmt.Errorf("found %+v matching External IDs", graphQLResourceResponse.Data.GraphSearch.TotalCount)
	}

	resourceId := graphQLResourceResponse.Data.GraphSearch.Nodes[0].Entities[0].ID
	return resourceId, nil
}
