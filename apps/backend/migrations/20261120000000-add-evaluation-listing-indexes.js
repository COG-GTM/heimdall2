'use strict';

const INDEXES = [
  {table: 'Evaluations', fields: ['createdAt'], name: 'evaluations_created_at'},
  {
    table: 'EvaluationTags',
    fields: ['evaluationId'],
    name: 'evaluation_tags_evaluation_id'
  },
  {
    table: 'GroupEvaluations',
    fields: ['evaluationId'],
    name: 'group_evaluations_evaluation_id'
  },
  {table: 'GroupUsers', fields: ['groupId'], name: 'group_users_group_id'}
];

module.exports = {
  up: async (queryInterface) => {
    return queryInterface.sequelize.transaction(async (transaction) => {
      for (const {table, fields, name} of INDEXES) {
        await queryInterface.addIndex(table, fields, {name, transaction});
      }
    });
  },

  down: async (queryInterface) => {
    return queryInterface.sequelize.transaction(async (transaction) => {
      for (const {table, name} of INDEXES) {
        await queryInterface.removeIndex(table, name, {transaction});
      }
    });
  }
};
